#include "crypto_utils.h"
#include <climits>
#include <iostream>
#include <limits.h>


int main(void) {
  std::cout<<mod_exp(7, 13, 20)<<std::endl;
  std::cout<<gcd(30ll, 15ll)<<std::endl;
  //std::cout<<LLONG_MAX<<std::endl;
  return 0;
}
