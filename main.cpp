#include <iostream>
#include "el_gamal.hpp"

#include <boost/program_options.hpp>

namespace po = boost::program_options;

void perform_sign();


int main_callback(int argc, char* argv[]) {
    po::options_description desc("Options");
    desc.add_options()
            ("help,h", "Please select sign or verify mode according to you needs." \
                       "Please provide correct arguments to the key pair." \
                       "There is no varranty of correctness of singature or verification is parameters are invalid")
            ("base,b", po::value<int>()->default_value(16), "Base of key pair and message")
            ("sign,s", po::value<bool>()->default_value(false), "Sign message mode")
            ("verify,v", po::value<bool>()->default_value(false), "Verify digital signature mode")
            ("message,m", po::value<std::string>()->default_value(""), "Message to sing/verify")
            ("p", po::value<std::string>()->default_value(""), "Prime p")
            ("g", po::value<std::string>()->default_value(""), "Generator g ")
            ("x", po::value<std::string>()->default_value(""), "Secret key x")
            ("y", po::value<std::string>()->default_value(""), "Public g^x")
            ("a", po::value<std::string>()->default_value(""), "a from digital signature")
            ("b", po::value<std::string>()->default_value(""), "b from digital signature");

    po::variables_map opts;

    try {
        po::store(po::parse_command_line(argc, argv, desc), opts);

        if (opts.count("help")) {
            desc.print(std::cout);
            return 1;
        }
    } catch (const std::exception& ce) {
        std::cout << "Exception occured while parsing commanf line arguments: "
                  << typeid (ce).name() << " " << ce.what() << std::endl;
        return 1;
    } catch (...) {
        std::cout << "Unknown exception occured while parsing commanf line arguments" << std::endl;
    }

    bool sign = opts["sign"].as<bool>();
    bool verify = opts["verify"].as<bool>();

    if ((sign && verify) || (!sign && !verify)) {
        std::cout << "Both sign and verify modes chosen or none of them. Aborting...";
        return 1;
    }

    if (sign) {
        auto message = opts["message"].as<std::string>();
        if (message.empty()) {
            std::cout << "Message is emtpy!!! Aborting...";
            return 1;
        }

        auto base = opts["base"].as<int>();
        if (base == 0) {
            std::cout << "Wrong base given. Aborting";
            return 1;
        }


        auto x_str = opts["x"].as<std::string>();
        auto y_str = opts["y"].as<std::string>();
        auto g_str = opts["g"].as<std::string>();
        auto p_str = opts["p"].as<std::string>();

        if (x_str.empty() || y_str.empty() || g_str.empty() || p_str.empty()) {
            std::cout << "Invalid key pair given. Aborting...";
        }

        auto m = mpz_class(message, base);
        auto p = mpz_class(p_str, base);
        auto g = mpz_class(g_str, base);
        auto x = mpz_class(x_str, base);

        mpz_class y;

        if (y_str.empty()) {
            mpz_powm_sec(y.get_mpz_t(), g.get_mpz_t(), x.get_mpz_t(), p.get_mpz_t());
        } else {
            y = mpz_class(y_str, base);
        }


        if (m >= p || x >= p || g >= p || y >= p) {
            std::cout << "Wrong parameters given. Aborting...";
            return false;
        }

        KeyPair kp = {p, g, y, x};

        auto ds = el_gamal::sign(m, kp);

        std::cout << "a: " << ds.a.get_str(16) << std::endl << "b: " << ds.b.get_str(16) ;

        return 0;
    }

    if (verify) {
        auto message = opts["message"].as<std::string>();
        if (message.empty()) {
            std::cout << "Message is emtpy!!! Aborting...";
            return 1;
        }

        auto base = opts["base"].as<int>();
        if (base == 0) {
            std::cout << "Wrong base given. Aborting";
            return 1;
        }


        auto y_str = opts["y"].as<std::string>();
        auto g_str = opts["g"].as<std::string>();
        auto p_str = opts["p"].as<std::string>();
        auto a_str = opts["a"].as<std::string>();
        auto b_str = opts["b"].as<std::string>();

        if (y_str.empty() || g_str.empty() || p_str.empty() || a_str.empty() || b_str.empty()) {
            std::cout << "Invalid public key given. Aborting...";
        }

        auto m = mpz_class(message, base);
        auto p = mpz_class(p_str, base);
        auto g = mpz_class(g_str, base);
        auto y = mpz_class(y_str, base);
        auto a = mpz_class(a_str, base);
        auto b = mpz_class(b_str, base);


        if (m >= p || g >= p || y >= p || a >= p || b >=p) {
            std::cout << "Wrong parameters given. Aborting...";
            return false;
        }

        PublicKey pk = {p, g, y};
        DigitalSignature ds = {a, b};


        auto result = el_gamal::verify(m, ds, pk);

        std::cout << "result: " << result;

        return 0;
    }

    return -1;
}

int main(int argc, char* argv[])
{
    auto res = main_callback(argc, argv);
    std::cout << std::endl;
    return  res;
}
