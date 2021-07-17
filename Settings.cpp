#include "Settings.h"
#include "Util.h"

#include <vector>
#include <fstream>
#include <sstream>

#define DELIM '='

#define KEY_DUMP_DIR           "DUMP_DIR"

//----

bool loadBoolean(const std::string &str, bool defaultVal)
{
    if (util::iequals(str, "True") || util::iequals(str, "on") || util::iequals(str, "yes")) {
        return true;
    }
    if (util::iequals(str, "False") || util::iequals(str, "off") || util::iequals(str, "no")) {
        return false;
    }
    return util::loadInt(str);
}

bool fillSettings(Settings &s, std::string line)
{
    std::vector<std::string> args;
    util::splitList(line, DELIM, args);

    if (args.size() < 2) {
        return false;
    }
    bool isFilled = false;
    std::string valName = args[0];
    std::string valStr = args[1];
    util::trim(valName);
    util::trim(valStr);

    if (util::iequals(valName, KEY_DUMP_DIR)) {
        s.outDir = valStr;
        isFilled = true;
    }
    return isFilled;
}

void stripComments(std::string &str)
{
    size_t found = str.find_first_of(";#");
    if (found != std::string::npos) {
        str = str.substr(0, found - 1);
    }
}

bool Settings::saveINI(const std::string filename)
{
    std::ofstream myfile(filename.c_str());
    if (!myfile.is_open()) {
        return false;
    }
    myfile << KEY_DUMP_DIR << DELIM << this->outDir << "\r\n";
    myfile.close();
    return true;
}

bool Settings::loadINI(const std::string filename)
{
    std::ifstream myfile(filename.c_str());
    if (!myfile.is_open()) {
        return false;
    }
    const size_t MAX_LINE = 300;
    char line[MAX_LINE] = { 0 };
    bool filledAny = false;

    while (!myfile.eof()) {
        myfile.getline(line, MAX_LINE);
        std::string lineStr = line;
        stripComments(lineStr);
        
        if (fillSettings(*this, lineStr)) {
            filledAny = true;
        }
    }
    return filledAny;
}
