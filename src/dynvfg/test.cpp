#include "pin.H"
#include <iostream>

int main (int argc, char* argv[]) {

    PIN_InitSymbols();

    if (PIN_Init(argc, argv)) {
        LOG("PIN_Init failed, check command line options\n");
        return -1;
    }

    PIN_StartProgram();
    return 0;
}