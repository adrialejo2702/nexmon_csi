#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

#include "edge-impulse-sdk/dsp/numpy.hpp"
#include "edge-impulse-sdk/classifier/ei_signal_with_range.h"
#include "edge-impulse-sdk/classifier/ei_run_classifier.h"

static std::vector<float> features;

static void print_json_string(const std::string &value) {
    for (char ch : value) {
        switch (ch) {
            case '\\': std::cout << "\\\\"; break;
            case '"': std::cout << "\\\""; break;
            case '\n': std::cout << "\\n"; break;
            case '\r': std::cout << "\\r"; break;
            case '\t': std::cout << "\\t"; break;
            default: std::cout << ch; break;
        }
    }
}

static bool load_features(const std::string &path, std::string &error) {
    std::ifstream input(path);
    if (!input) {
        error = "No se pudo abrir el fichero de features: " + path;
        return false;
    }

    features.clear();
    std::string token;
    while (input >> token) {
        try {
            features.push_back(std::stof(token));
        }
        catch (const std::exception &) {
            error = "Valor numerico no valido en features: " + token;
            return false;
        }
    }

    if (features.size() != EI_CLASSIFIER_DSP_INPUT_FRAME_SIZE) {
        std::ostringstream oss;
        oss << "El modelo espera " << EI_CLASSIFIER_DSP_INPUT_FRAME_SIZE
            << " features, pero se recibieron " << features.size();
        error = oss.str();
        return false;
    }
    return true;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        std::cerr << "Uso: " << argv[0] << " <features.txt>\n";
        return 2;
    }

    std::string error;
    if (!load_features(argv[1], error)) {
        std::cout << "{\"success\":false,\"error\":\"";
        print_json_string(error);
        std::cout << "\",\"result\":{}}\n";
        return 1;
    }

    signal_t signal;
    signal.total_length = features.size();
    signal.get_data = [](size_t offset, size_t length, float *out_ptr) {
        if (offset + length > features.size()) {
            return -1;
        }
        std::copy(features.begin() + offset, features.begin() + offset + length, out_ptr);
        return 0;
    };

    ei_impulse_result_t result = { 0 };
    EI_IMPULSE_ERROR res = run_classifier(&signal, &result, false);
    if (res != EI_IMPULSE_OK) {
        std::ostringstream oss;
        oss << "run_classifier fallo con codigo " << static_cast<int>(res);
        std::cout << "{\"success\":false,\"error\":\"";
        print_json_string(oss.str());
        std::cout << "\",\"result\":{}}\n";
        return 1;
    }

    std::cout << "{\"success\":true,\"error\":null,\"result\":{";
    for (size_t ix = 0; ix < EI_CLASSIFIER_LABEL_COUNT; ix++) {
        if (ix > 0) {
            std::cout << ",";
        }
        std::cout << "\"";
        print_json_string(result.classification[ix].label ? result.classification[ix].label : "");
        std::cout << "\":" << result.classification[ix].value;
    }
    std::cout << "},\"timing\":{";
    std::cout << "\"dsp\":" << result.timing.dsp << ",";
    std::cout << "\"classification\":" << result.timing.classification << ",";
    std::cout << "\"anomaly\":" << result.timing.anomaly;
    std::cout << "}}\n";
    return 0;
}
