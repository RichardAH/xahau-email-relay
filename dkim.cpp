typedef int _Bool;
#include <iostream>
#include <string>
#include <vector>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <opendkim/dkim.h>

class EmailVerifier {
private:
    DKIM_LIB* dkim_lib;
    DKIM* dkim;
    std::vector<std::string> headers;
    std::string body;
    std::string from_address;
    std::string from_domain;
    std::string dkim_domain;

    void parse_email(const std::string& email)
    {
        std::istringstream stream(email);
        std::string line;

        while (std::getline(stream, line))
        {
            if (line.empty() || line == "\r")
                break;

            // Handle header line continuations
            while (stream.peek() == ' ' || stream.peek() == '\t') {
                std::string continuation;
                std::getline(stream, continuation);
                line += '\n' + continuation;
            }
            if (!line.empty()) {
                headers.push_back(line.substr(0, line.size() - (line.back() == '\r' ? 1 : 0)));
            }
        }

        std::ostringstream body_stream;
        while (std::getline(stream, line))
            body_stream << line << "\n";
        body = body_stream.str();
    }

    void extract_from_address()
    {
        static const std::regex
            from_regex(R"(^From:\s*(?:.*<)?([^<>\s]+@[^<>\s]+)(?:>)?)", std::regex::icase);

        for (const auto& header : headers)
        {
            std::smatch match;
            if (std::regex_search(header, match, from_regex) && match.size() > 1)
            {
                from_address = match[1].str();
                from_domain = get_domain_from_address(from_address);
                return;
            }
        }
    }

    static std::string get_domain_from_address(const std::string& addr)
    {
        auto at_pos = addr.find('@');
        return (at_pos != std::string::npos) ? addr.substr(at_pos + 1) : "";
    }

    void set_dkim_domain()
    {
        DKIM_SIGINFO* sig = dkim_getsignature(dkim);
        dkim_domain = sig 
            ? reinterpret_cast<char const*>(reinterpret_cast<void const*>(dkim_sig_getdomain(sig)))
            : "";
    }

    static bool
        check_domain_alignment(
                const std::string& from_domain, const std::string& dkim_domain, bool strict = false)
    {
        if (strict)
            return from_domain == dkim_domain;

        auto extract_org_domain = [](const std::string& domain)
        {
            auto last_dot = domain.find_last_of('.');
            if (last_dot == std::string::npos)
                return domain;
            auto second_last_dot = domain.find_last_of('.', last_dot - 1);
            return (second_last_dot == std::string::npos)
                ? domain
                : domain.substr(second_last_dot + 1);
        };

        return extract_org_domain(from_domain) == extract_org_domain(dkim_domain);
    }

    bool sane_ = true;
public:

    bool sane()
    {
        return sane_;
    }

    explicit EmailVerifier(const std::string& email) : dkim_lib(dkim_init(nullptr, nullptr)), dkim(nullptr)
    {
        if (!dkim_lib)
        {
            sane_ = false;
            return;
            //throw std::runtime_error("Failed to initialize DKIM library");
        }

        parse_email(email);
        extract_from_address();

        DKIM_STAT status;
        dkim = dkim_verify(dkim_lib, (uint8_t const*)"id", nullptr, &status);
        if (!dkim)
        {
            sane_ = false;
            return;
//            throw std::runtime_error("Failed to create DKIM verification handle");
        }
    }

    ~EmailVerifier() {
        if (dkim) dkim_free(dkim);
        if (dkim_lib) dkim_close(dkim_lib);
    }

    EmailVerifier(const EmailVerifier&) = delete;
    EmailVerifier& operator=(const EmailVerifier&) = delete;
    EmailVerifier(EmailVerifier&&) = delete;
    EmailVerifier& operator=(EmailVerifier&&) = delete;

    bool verify_dkim()
    {
        if (!sane_)
            return false;

        DKIM_STAT status;

        for (const auto& header : headers)
        {
            status = dkim_header(dkim, (unsigned char*)header.c_str(), header.length());
            if (status != DKIM_STAT_OK) {
                std::cerr << "Failed to process header: " << dkim_geterror(dkim) << std::endl;
                return false;
            }
        }

        status = dkim_eoh(dkim);
        if (status != DKIM_STAT_OK)
        {
            std::cerr << "DKIM EOH error: " << dkim_geterror(dkim) << std::endl;
            return false;
        }

        status = dkim_body(dkim, (unsigned char*)body.c_str(), body.length());
        if (status != DKIM_STAT_OK)
        {
            std::cerr << "Failed to process body: " << dkim_geterror(dkim) << std::endl;
            return false;
        }

        _Bool testkey;
        status = dkim_eom(dkim, &testkey);
        if (status != DKIM_STAT_OK)
        {
            std::cerr << "DKIM EOM error: " << dkim_geterror(dkim) << std::endl;
            return false;
        }

        DKIM_SIGINFO* sig = dkim_getsignature(dkim);
        if (!sig)
        {
            std::cerr << "No DKIM signature found" << std::endl;
            return false;
        }

        if (dkim_sig_getbh(sig) != DKIM_SIGBH_MATCH)
        {
            std::cerr << "DKIM body hash mismatch" << std::endl;
            return false;
        }

        set_dkim_domain();

        return status == DKIM_STAT_OK;
    }

    bool verify_email()
    {
        if (!sane_)
            return false;

        if (!verify_dkim())
        {
            std::cerr << "DKIM verification failed" << std::endl;
            return false;
        }

        if (from_address.empty())
        {
            std::cerr << "Failed to extract From address" << std::endl;
            return false;
        }

        if (!check_domain_alignment(from_domain, dkim_domain, false))
        {
            std::cerr << "from_domain: " << from_domain << ", dkim_domain: " << dkim_domain << std::endl;
            std::cerr << "DKIM alignment check failed" << std::endl;
            return false;
        }

        return true;
    }
};

int main()
{
    std::string raw_email{std::istreambuf_iterator<char>(std::cin), std::istreambuf_iterator<char>()};

    if (raw_email.empty())
    {
        std::cerr << "Error: No email content received from stdin." << std::endl;
        return 1;
    }

    try {
        EmailVerifier verifier(raw_email);
        if (!verifier.sane())
        {
            std::cout << "Could not spawn verifier\n";
            return 2;
        }

        bool is_valid = verifier.verify_email();
        std::cout << "Email is " << (is_valid ? "valid" : "invalid") << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
