# Pin'n'Sieve

[![GitHub release](https://img.shields.io/github/release/hasherezade/pin_and_sieve.svg)](https://github.com/hasherezade/pin_n_sieve/releases)

 A dynamic malware unpacker based on Intel Pin and PE-sieve (deploys PE-sieve scan on specific triggers).
 
### WARNING: this is an *experimental version*

How to build?
-
To compile the prepared project you need to use [Visual Studio >= 2012](https://visualstudio.microsoft.com/downloads/). It was tested with [Intel Pin 3.19](https://software.intel.com/en-us/articles/pin-a-binary-instrumentation-tool-downloads).<br/>

1. Clone this repo into `\source\tools` that is inside your Pin root directory.
2. Open the project in Visual Studio. 
3. Modify the file [my_paths.h](https://github.com/hasherezade/pin_n_sieve/blob/main/my_paths.h), and set the path to `windows.h` into `_WINDOWS_H_PATH_`, appropriate to your environment.
4. The other installation steps are analogous to the ones explained in [this Wiki](https://github.com/hasherezade/tiny_tracer/wiki/Installation).
