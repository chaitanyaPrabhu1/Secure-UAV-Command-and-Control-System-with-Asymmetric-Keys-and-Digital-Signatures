#include "crypto_utils.h"
#include <cstdlib>
#include <iostream>
#include <vector>
#include <math.h>

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

// euclidean algorithm
// gcd(a, b) = gcd(a mod b, b) recursively



// extended euclidean algorithm(EEA)
// 56x + 15y = gcd(56, 15)
// 56 = 15.3 + 11
// 15 = 11.1 + 4
// 11 = 4.2 + 3
// 4 = 3.1 + 1
// 3 = 1.3 + 0
// gcd(56, 15) = 1

 ll gcd(ll a, ll b, int &x, int &y){
  if (b == 0) {
    x = 1;
    y = 0;

    return a;
  }

  int x1, y1;
  int d = gcd(b, a % b, x1, y1);
  x = y1;
  y = x1 - y1 * (a / b);

  return d;
}



ll inv_mod(ll a, ll b) {
  int x, y;
  int g = gcd(a, b, x, y);

  if (g != 1) {
    return -1ll;
  }else {
    return (x%b + b)%b;
  }
}

