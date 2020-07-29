#include <iostream>
#include <vector>
#include <string>

using namespace std;

int main()
{
    vector<string> msg {"Paillier", "cryptosystem", "in", "C/C++"};

    for (const string& word : msg)
    {
        cout << word << " ";
    }
    cout << endl;
}