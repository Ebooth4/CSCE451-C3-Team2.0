#include <stdio.h>
#include <string.h>
#include <string>

using namespace std;

char drink = 'c';
int drinkAmount = 0;

void option();

int pepsi(){

    return 1;

}

int coke(){

    option();

    return 0;

}

int fanta(){

    return 1;

}

void option(){
    switch(drink){
        case 'c':
            drinkAmount = coke();
            break;
        case 'p':
            drinkAmount = pepsi();
            break;
        case 'f':
            drinkAmount = fanta();
            break;
        default:
            break;
    }
}

int main() {

    option();

}