#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#define ll long long int

ll mod_exp(ll b, ll e, ll p); // (b)^e mod(p)
ll inv_mod(ll a, ll m); // (b^-e)mod(p)
ll gcd(ll a, ll b, int &x, int &y);           // gcd(a, b)
#endif
