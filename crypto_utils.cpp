#include "crypto_utils.h"
#include <vector>
#include <iostream>

#define ll long long int

ll  mod_exp(ll  b,  ll e, ll p) {
  std::vector<ll>bi;
  int i = 0;
  while (e) {
    bi.push_back(e%2);
    e = e/2;
  }


  ll result = 1;
  for(int i =(int)bi.size()-1; i >= 0;){
    result = (result * result)%p;// avoiding overflowing
    if(bi[i]){
        result *= b;
    }
    result = result % p;
    i--;
  }


  return result;
}
