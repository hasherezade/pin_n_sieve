#pragma once

#include <iostream>

class Settings {

public:
    Settings() :
        outDir("C:\\scans\\")
    {
    }

    bool loadINI(const std::string filename);
    bool saveINI(const std::string filename);

    std::string outDir;
};
