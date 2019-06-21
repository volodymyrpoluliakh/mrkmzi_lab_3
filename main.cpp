#include <iostream>
#include "el_gamal.hpp"

#include <boost/program_options.hpp>
#include <chrono>

namespace po = boost::program_options;



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
            ("test,t", po::value<bool>()->default_value(false), "Test mode")
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
    bool test = opts["test"].as<bool>();

    int mod_cnt = sign + verify + test;



    if (mod_cnt != 1) {
        std::cout << "Multiple modes chosen or none of them. Aborting...";
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

    try {
        if (test) {
            {
                auto m = mpz_class("5899480792826456006443885152450880125009055116814742090110946562327522344198071207928223258613074769865443678822870204074423506819999778714283571640436768", 10);
                auto p = mpz_class("8fef4f1de5ffd97a15d28d7dfa90c3f4dd519a08ccc5fca707c6ff88c72c469f40edd1d79e04e75ffd8034b1c744bdbb82e5bd93fffb9bf8c94665551779aede", 16);
                auto x = mpz_class("68f879302a776ef21ad93f81f1db11d863b0dc91520edce7a7b0d86b0b1e7310c39e8859fbb6ec6371eec68f6aecbb5783314d2b6e74fd4c737706f7ebbd5eb8", 16);

                auto g = mpz_class("2", 16);
                auto y = mpz_class();
                mpz_powm(y.get_mpz_t(), g.get_mpz_t(), x.get_mpz_t(), p.get_mpz_t());

                KeyPair kp = {p, g, y, x};

                {
                    auto t1 = std::chrono::high_resolution_clock::now();
                    auto ds1 = el_gamal::sign(m, kp);
                    auto ds2 = el_gamal::sign(m, kp);
                    auto ds3 = el_gamal::sign(m, kp);
                    auto ds4 = el_gamal::sign(m, kp);
                    auto ds5 = el_gamal::sign(m, kp);
                    auto t2 = std::chrono::high_resolution_clock::now();
                    std::cout << "512 bits: "
                              << std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count()  << " us" << std::endl;
                }
            }

            {
                auto m = mpz_class("5899480792826456006443885152450880125009055116814742090110946562327522344198071207928223258613074769865443678822870204074423506819999778714283571640436768", 10);
                auto p = mpz_class("55701615ba1defde5064b5c4f8703c97cc99304968a8a1ed8ed3b59d8ecb2a5c2467e05b5a55b96a2ad980581b0b1a68038b6e15f66f2fc762d9125830cb9a00816d240e25119f196cbbc232f468a8fda3839afb91f6e1446d6ff91d536b80a720e3c529fcd47c73776057f103ff70c4060dc5a345a35a5ca8b7e6e474487045", 16);
                auto x = mpz_class("202e67b91df51b15637d75b144f7de6eac43cd013359e2847879d5358764c25621e0e70967282fc06a957cefe58cc56010fe604c8f75d07d59078f37b83d6e3e26d7aa24846478bef7554ce16e6cc5d1d2e890aecf70b694692ca95bb2957ab87acbfbbf1a241cfad03be74da35eb554959de295711baf752d672559fb087fbe", 16);

                auto g = mpz_class(2);
                auto y = mpz_class();
                mpz_powm_sec(y.get_mpz_t(), g.get_mpz_t(), x.get_mpz_t(), p.get_mpz_t());

                KeyPair kp = {p, g, y, x};

                {
                    auto t1 = std::chrono::high_resolution_clock::now();
                    auto ds1 = el_gamal::sign(m, kp);
                    auto ds2 = el_gamal::sign(m, kp);
                    auto ds3 = el_gamal::sign(m, kp);
                    auto ds4 = el_gamal::sign(m, kp);
                    auto ds5 = el_gamal::sign(m, kp);
                    auto t2 = std::chrono::high_resolution_clock::now();
                    std::cout << "1024 bits: "
                              << std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count()  << " us" << std::endl;
                }
            }

            {
                auto m = mpz_class("5899480792826456006443885152450880125009055116814742090110946562327522344198071207928223258613074769865443678822870204074423506819999778714283571640436768", 10);
                auto p = mpz_class("7f18cebe4ce956b71fd418a6814336ec750f0e68637463621b10d5be336a1972151c4790f20b1f90a58bbd147fe1bd14aed9fd2fba10c08d6f1fd2bdf37e068337baf9ed67382f4f210268225f4c286c13ab744557584ce4dc5dc78d41c6bdb955dc3f6eee9af69740958636584823524f43e437b86e8d9d7a91da3133221b4025dc0af26e3b08ba28833d726dbc101729a6929dfde56ebb273d028422c775138968e03582ffb9e5483c8f03a4eaba1362420b35a69d21ee6aed372011f301f6f8741130204d72eac0e9d79740022dbf1445769176a70a19825a5fd7f5a82568847eb4a0f1b22576e42014460aadfd318e14e219613f69c19d8d6e8d248ea67f", 16);
                auto x = mpz_class("3ffde4d523c799281ec1c7014147039e2d674a7654d069fa54cc9e9ca6bf62d2fa961c289800c98a2802abacd007ef6d2283e19e40fd13a5effc176c08ef9e71e266048ee8f2180b6f902d35809790b20e63fafc07f2f345e93e3aa9fd8f6e017c8c3d7c59d73ee5c1ad39d923072cecd3ca556a30148bc370425435d3b7d9213e2bb1d22b82e7c1c79b7332240113429bd95c4591bae96e5b09194768eb644957a362d4da95862a4a424ef93854428383b5924d81f2e8901eea1cd3a643819af9b6d3a0f9c6721b00be8405d1a00c8e83357c9c90b7eac126db7a947edb700ec9a79f5f8f1464a5efad27ae9a9eab99811333c9a4289bcc8a01deb7aebf250b", 16);

                auto g = mpz_class(2);
                auto y = mpz_class();
                mpz_powm_sec(y.get_mpz_t(), g.get_mpz_t(), x.get_mpz_t(), p.get_mpz_t());

                KeyPair kp = {p, g, y, x};

                {
                    auto t1 = std::chrono::high_resolution_clock::now();
                    auto ds1 = el_gamal::sign(m, kp);
                    auto ds2 = el_gamal::sign(m, kp);
                    auto ds3 = el_gamal::sign(m, kp);
                    auto ds4 = el_gamal::sign(m, kp);
                    auto ds5 = el_gamal::sign(m, kp);
                    auto t2 = std::chrono::high_resolution_clock::now();
                    std::cout << "2048 bits: "
                              << std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count()  << " us" << std::endl;
                }
            }

            return 0;
        }
    } catch (const std::exception& ce) {
        std::cout << typeid (ce).name() << " " << ce.what() << std::endl;
    } catch (...) {
        std::cout << "unknown exception occured";
    }

    return -1;
}

int main(int argc, char* argv[])
{
    auto res = main_callback(argc, argv);
    std::cout << std::endl;
    return  res;
}
