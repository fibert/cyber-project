#include <UI.h>
#include <agent.h>

int c = 0;

void agentMain() {
     c = (c + 1) % 3;

     if (c == 0) {
         setGreen();
     }
     else if (c == 1) {
         setYellow();
     }
     else if (c == 2) {
         setRed();
     }
    return;
}