#include "stdafx.h"
#include <iostream>
#include <vector>
#include <map>
#include <fstream>
#include <windows.h>
#include <ctime>
#include <openssl/des.h>
using namespace std;

#define ENC_MODE 0
#define DEC_MODE 1

//binary representation of char
struct binary_repr{
	unsigned null_bit : 1;
	unsigned first_bit : 1;
	unsigned second_bit : 1;
	unsigned third_bit : 1;
	unsigned fourth_bit : 1;
	unsigned fifth_bit : 1;
	unsigned sixth_bit : 1;
	unsigned seventh_bit : 1;
};

//char and binary repr. share the same memory area
union char_bin_form{
	binary_repr a;
	char ch;
};

//class for DES cipher
class DES_Cipher{
private:
	DES_key_schedule key1;//key schedule for the first key
	DES_key_schedule key2;//key schedule for the second key
	int b_part;//padding if (size of plain text)%8!=0  
	vector<char> plain_text;
	vector<char> enc_text;
	vector<char> dec_text;
	vector<char> ciph_key;
	vector<char> ciph_key1;
	vector<char> ciph_key2;
	vector<char> double_enc_text;
protected:
	//
	//Setters
	void SetCiphKey1(vector<char> k1){ ciph_key1 = k1; }
	void SetCiphKey2(vector<char> k2){ ciph_key2 = k2; }
	void SetEncText(vector<char> e){ enc_text = e; }
	void SetDecText(vector<char> d){ dec_text = d; }
	void SetDoubleEncText(vector<char> e_text){ double_enc_text = e_text; }
	void SetPlainText(vector<char> p_t){ plain_text = p_t; }
	void SetPaddingPart(int b_p){ b_part = b_p; }
	void SetKeySchedule1(DES_key_schedule key_s){ key1 = key_s; }
	void SetKeySchedule2(DES_key_schedule key_s){ key2 = key_s; }
	void SetCiphKey(vector<char> k){ ciph_key = k; }
	//Getters
	vector<char> GetPlainText(){ return plain_text; }
	vector<char> GetEncText(){ return enc_text; }
	vector<char> GetDecText(){ return dec_text; }
	vector<char> GetDoubleEncText(){ return double_enc_text; }
	int GetKeyLen(){ return ciph_key.size(); }	
	int GetTextLen(){ return plain_text.size();}
	vector<char> GetCiphKey(){ return ciph_key; };
	DES_key_schedule GetKeySchedule1(){ return key1; }
	DES_key_schedule GetKeySchedule2(){ return key2; }
	int GetPaddingPart(){ return b_part; }
	
	vector<char> IntToBin(int numb);
	vector<char> KeyToChar(vector<char> key);
	void WriteToFile(string file_name);//write deciphered text to file
	void Encrypt();
	void Decrypt();
	//for MITM
public:
	DES_Cipher(){ b_part = 0; }
	vector<char> GetCiphKey1(){ return ciph_key1; }
	vector<char> GetCiphKey2(){ return ciph_key2; }
	void PrintBinKey(vector<char>& bin_vect_key);
	void ReadFile(string file_name);//read file with text for encryption
	vector<char> StringKeyRepr(char *key);
	void PrintKey(vector<char> vect);
	void GenerateCipherKey();
	void EncryptDouble(vector<char> key_1, vector<char> key_2);
	map<vector<char>, vector<char>> CreateSecondKeyMap(vector<char> known_key, int bits_to_guess);
	map<vector<char>, vector<char>> CreateFirstKeyMap(vector<char> known_key, int bits_to_guess);
	void FindKeys(map<vector<char>, vector<char>> &enc_map, map<vector<char>, vector<char>> &dec_map);
	map<vector<char>, vector<char>> Map_BitsToGuessInsideOneKey(vector<char> known_bits_left, vector<char> known_bits_right, int beg_point, int end_point,int mode);//mode: 0 - encryption, 1 - decryption
};


void DES_Cipher::ReadFile(string file_name)
{
	char ch;
	ifstream input_file(file_name);
	if (input_file){
		while (input_file.get(ch)){
			plain_text.push_back(ch);
		}
	}
	else{
		return;
	}
}

void DES_Cipher::WriteToFile(string file_name)
{
	ofstream output_file(file_name);
	vector<char>::iterator it;
	if (output_file){
		for (it = dec_text.begin(); it < dec_text.end(); it++){
			output_file << *it;
		}
		output_file << "\n";
	}
}

void DES_Cipher::Decrypt()
{
	vector<char> e_text;
	vector<char> dec_text;//decrypted text without padding
	DES_cblock buf;
	DES_cblock dec_block;
	int block_part;
	//block_part = GetPaddingPart();
	e_text = GetDoubleEncText();
	for (int i = 0; i <= e_text.size(); i++){
		if (i % 8 == 0 && i>0){
			DES_ecb_encrypt(&buf, &dec_block, &key2, 0);
			for (int j = 0; j < 8; j++){
				dec_text.push_back(dec_block[j]);
			}
		}
		if (i != e_text.size()){
			buf[i % 8] = e_text[i];
		}
	}
	SetDecText(dec_text);//decrypted text
}

void DES_Cipher::Encrypt()
{
	vector<char> text;
	vector<char> cipher_text;
	DES_cblock buf;
	DES_cblock cipher_block;
	text = GetPlainText();
	int block_part = 0;
	//if size of text is not fit
	if (text.size() % 8 != 0){
		block_part = text.size() % 8;
		SetPaddingPart(block_part);
		for (int j = block_part; j < 8; j++){
			text.push_back(0);//padding with 0
		}
	}
	for (int i = 0; i <= text.size(); i++){
		if (i % 8 == 0 && i>0){//if we have block of 64 bits
			DES_ecb_encrypt(&buf, &cipher_block, &key1, 1);
			for (int j = 0; j < 8; j++){//copy new key
				cipher_text.push_back(cipher_block[j]);
			}
		}
		if (i != text.size()){
			buf[i % 8] = text[i];
		}
	}
	SetEncText(cipher_text);
}


void DES_Cipher::GenerateCipherKey()
{
	DES_key_schedule key1;
	DES_key_schedule key2;
	DES_cblock key_1;
	DES_cblock key_2;
	vector<char> key_vect1;
	vector<char> key_vect2;
	string str_key="";
	srand(time(NULL));
	for (int i = 0; i < 7; i++){
		key_vect1.push_back(rand() % 92 + 33);
		str_key += key_vect1[i];
	}
	DES_string_to_key(str_key.c_str(), &key_1);
	DES_set_key_checked(&key_1, &key1);
	//Sleep(20);
	str_key = "";
	for (int i = 0; i < 7; i++){
		key_vect2.push_back(rand() % 92 + 33);
		str_key += key_vect2[i];
	}
	DES_string_to_key(str_key.c_str(), &key_2);
	DES_set_key_checked(&key_2, &key2);
	
	//SetKeySchedule(key);
	SetCiphKey1(key_vect1);
	SetCiphKey2(key_vect2);
}




//Printing binary representation of key
void DES_Cipher::PrintBinKey(vector<char>& bin_vect_key)
{
	//int counter = 112;
	int counter = 0;
	for (int i = 0; i<bin_vect_key.size(); i++)
	{
		if (counter % 8 == 0 && counter != 0){
			cout << "\n";
		}
		cout << bin_vect_key[i];
		counter++;
	}
	cout << "\n";
}

//Representation of key in binary form
//little endian
vector<char> DES_Cipher::StringKeyRepr(char *key)
{
	char_bin_form bin_key[14];
	vector<char> bin_vect_key;
	int counter = 112;
	for (int i = 0; i < 14; i++){
		bin_key[i].ch = key[i];
	}
	for (int i = 0; i < 14; i++){
		/*
		bin_vect_key.push_back(bin_key[i].a.null_bit+'0');
		bin_vect_key.push_back(bin_key[i].a.first_bit+'0');
		bin_vect_key.push_back(bin_key[i].a.second_bit+'0');
		bin_vect_key.push_back(bin_key[i].a.third_bit+'0');
		bin_vect_key.push_back(bin_key[i].a.fourth_bit+'0');
		bin_vect_key.push_back(bin_key[i].a.fifth_bit+'0');
		bin_vect_key.push_back(bin_key[i].a.sixth_bit+'0');
		bin_vect_key.push_back(bin_key[i].a.seventh_bit+'0');
		*/
		bin_vect_key.push_back(bin_key[i].a.seventh_bit + '0');
		bin_vect_key.push_back(bin_key[i].a.sixth_bit + '0');
		bin_vect_key.push_back(bin_key[i].a.fifth_bit + '0');
		bin_vect_key.push_back(bin_key[i].a.fourth_bit + '0');
		bin_vect_key.push_back(bin_key[i].a.third_bit + '0');
		bin_vect_key.push_back(bin_key[i].a.second_bit + '0');
		bin_vect_key.push_back(bin_key[i].a.first_bit + '0');
		bin_vect_key.push_back(bin_key[i].a.null_bit + '0');
	}
	for (int i = 111; i >= 0; i--)
	{
		if (counter % 8 == 0 && counter!=112){
			cout << "\n";
		}
		cout << bin_vect_key[i];
		counter--;
	}
	cout << "\n";


	return bin_vect_key;
}

//binary representation of integer
vector<char> DES_Cipher::IntToBin(int numb)
{
	int temp;
	vector<char> new_numb;
	do
	{
		temp = numb % 2;
		numb /= 2;
		switch (temp){
		case 0:
			new_numb.push_back('0');
			break;
		case 1:
			new_numb.push_back('1');
			break;
		}

	} while (numb != 0 && numb != 1);
	if (numb == 1){
		new_numb.push_back('1');
	}
	return new_numb;
}

//char representation of bin vector
vector<char> DES_Cipher::KeyToChar(vector<char> key)
{
	char char_repr[8];
	vector<char> new_key;
	char_bin_form new_char;
	int j = 0;
	for (int i = 0; i < key.size(); i++){
		char_repr[j] = key[i];
		j++;
		if ((j % 8 == 0 && j != 0)||i==(key.size()-1)){
			new_char.a.seventh_bit = char_repr[0] - '0';
			new_char.a.sixth_bit = char_repr[1] - '0';
			new_char.a.fifth_bit = char_repr[2] - '0';
			new_char.a.fourth_bit = char_repr[3] - '0';
			new_char.a.third_bit = char_repr[4] - '0';
			new_char.a.second_bit = char_repr[5] - '0';
			new_char.a.first_bit = char_repr[6] - '0';
			new_char.a.null_bit = char_repr[7] - '0';
			new_key.push_back(new_char.ch);
			j = 0;
		}
	}
	return new_key;
}

//Double encryption
void DES_Cipher::EncryptDouble(vector<char> key_1, vector<char> key_2)
{
	vector<char> text;
	vector<char> cipher_text1;
	vector<char> cipher_text2;
	DES_cblock buf;
	DES_cblock cipher_block1;
	DES_cblock cipher_block2;
	DES_cblock key_cblock;
	DES_key_schedule key_sched_1;
	DES_key_schedule key_sched_2;
	DES_cblock des_key1;
	DES_cblock des_key2;
	text = GetPlainText();
	int block_part = 0;
	string str_key1=""; 
	string str_key2="";
	for (int i = 0; i < key_1.size(); i++){
		str_key1 += key_1[i];
		str_key2 += key_2[i];
	}
	DES_string_to_key(str_key1.c_str(), &des_key1);
	DES_string_to_key(str_key2.c_str(), &des_key2);
	DES_set_key_checked(&des_key1, &key_sched_1);
	SetKeySchedule1(key_sched_1);
	SetCiphKey(key_1);
	DES_set_key_checked(&des_key2, &key_sched_2);
	SetKeySchedule2(key_sched_2);
	SetCiphKey(key_2);
	//now work with plaintext
	if (text.size() % 8 != 0){
		block_part = text.size() % 8;
		SetPaddingPart(block_part);
		for (int j = block_part; j < 8; j++){
			text.push_back(0);//padding with 0
		}
	}
	for (int i = 0; i <= text.size(); i++){
		if (i % 8 == 0 && i>0){//if we have block of 64 bits
			DES_ecb_encrypt(&buf, &cipher_block1, &key1, 1);
			for (int j = 0; j < 8; j++){//copy new key
				cipher_text1.push_back(cipher_block1[j]);
			}
		}
		if (i != text.size()){
			buf[i % 8] = text[i];
		}
	}
	//SetEncText(cipher_text1);
	for (int i = 0; i <= cipher_text1.size(); i++){
		if (i % 8 == 0 && i>0){//if we have block of 64 bits
			DES_ecb_encrypt(&buf, &cipher_block2, &key2, 1);
			for (int j = 0; j < 8; j++){//copy new key
				cipher_text2.push_back(cipher_block2[j]);
			}
		}
		if (i != cipher_text1.size()){
			buf[i % 8] = cipher_text1[i];
		}
	}
	SetDoubleEncText(cipher_text2);//after double des
}

//Map for decryption
map<vector<char>, vector<char>> DES_Cipher::CreateSecondKeyMap(vector<char> known_key, int bits_to_guess)
{
	vector<char> additional_number;
	vector<char> possible_key;
	vector<char> possible_key1;
	map<vector<char>, vector<char>> key_map_2;
	DES_cblock key_2;
	DES_key_schedule key;//64-bit key for encryption
	string str_key="";
	int cnt;
	srand(time(NULL));
	for (int i = 0; i < pow(2, bits_to_guess); i++){
		possible_key = known_key;
		additional_number = IntToBin(i);//number that we add to our known key(adding to the left; little endian)
		cnt = additional_number.size();
		for (int j = 0; j < bits_to_guess - cnt; j++){
			additional_number.push_back('0');
		}
		for (int k = 0; k < bits_to_guess; k++){
			possible_key.insert(possible_key.begin(),1,additional_number[k]);//inserting to the beginning
		}
		possible_key1=KeyToChar(possible_key);//get char representation of new key
		for (int i = 0; i < possible_key1.size(); i++){
			str_key += possible_key1[i];
		}
		DES_string_to_key(str_key.c_str(), &key_2);//get key for des with odd parity
		DES_set_key_checked(&key_2, &key);
		SetKeySchedule2(key);//set our key schedule
		SetCiphKey(possible_key1);
		Decrypt();//now we decrypt twice encrypted earlear plain text with this key
		key_map_2.insert(make_pair(GetDecText(), possible_key1));//fill the map
		possible_key.clear();
		possible_key1.clear();
		str_key = "";
	}
	return key_map_2;
}

//Map for encryption
map<vector<char>, vector<char>> DES_Cipher::CreateFirstKeyMap(vector<char> known_key, int bits_to_guess)
{
	vector<char> additional_number;
	vector<char> possible_key;
	vector<char> possible_key1;
	vector<char> key_without_parity;
	map<vector<char>, vector<char>> key_map_1;
	DES_cblock key_1;
	DES_key_schedule key;
	string str_key="";
	int cnt;
	srand(time(NULL));
	for (int i = 0; i < pow(2,bits_to_guess); i++){
		possible_key = known_key;
		additional_number=IntToBin(i);
		cnt = additional_number.size();
		for (int j = 0; j < bits_to_guess - cnt; j++){
			additional_number.push_back('0');
		}
		for (int k = bits_to_guess - 1; k >= 0; k--){
			possible_key.push_back(additional_number[k]);
		}
		possible_key1=KeyToChar(possible_key);
		for (int i = 0; i < possible_key1.size(); i++){
			str_key += possible_key1[i];
		}
		DES_string_to_key(str_key.c_str(), &key_1);
		DES_set_key_checked(&key_1, &key);
		SetKeySchedule1(key);
		SetCiphKey(possible_key1);
		Encrypt();//now we encrypt our plaintext with this key
		key_map_1.insert(make_pair(GetEncText(), possible_key1));
		possible_key.clear();
		possible_key1.clear();
		str_key = "";
	}
	return key_map_1;
}

map<vector<char>, vector<char>> DES_Cipher::Map_BitsToGuessInsideOneKey(vector<char> known_bits_left, vector<char> known_bits_right, int beg_point, int end_point,int mode)
{
	vector<char> additional_number;
	vector<char> possible_key;
	vector<char> possible_key1;
	vector<char> key_without_parity;
	map<vector<char>, vector<char>> key_map_1;
	map<vector<char>, vector<char>> key_map_2;
	DES_cblock key_1;
	DES_key_schedule key;
	string str_key = "";
	int cnt;
	int counter=0;
	srand(time(NULL));
	for (int i = 0; i < pow(2,(end_point - beg_point));i++){
		//form known left side
		possible_key = known_bits_left;
		//bits that we insert between two known parts
		additional_number = IntToBin(i);
		cnt = additional_number.size();
		for (int j = 0; j < (end_point - beg_point) - cnt; j++){
			additional_number.push_back('0');
		}
		for (int k = ((end_point - beg_point) - 1); k >= 0; k--){
			possible_key.push_back(additional_number[k]);
		}
		//now we need to connect known right side
		for (int m = 0; m<known_bits_right.size(); m++){
			possible_key.push_back(known_bits_right[m]);
		}
		possible_key1 = KeyToChar(possible_key);
		for (int i = 0; i < possible_key1.size(); i++){
			str_key += possible_key1[i];
		}
		DES_string_to_key(str_key.c_str(), &key_1);
		DES_set_key_checked(&key_1, &key);
		if (mode == ENC_MODE){
			SetKeySchedule1(key);
			SetCiphKey(possible_key1);
			Encrypt();//now we encrypt our plaintext with this key
			key_map_1.insert(make_pair(GetEncText(), possible_key1));
		}
		if (mode == DEC_MODE){
			counter++;
			SetKeySchedule2(key);
			SetCiphKey(possible_key1);
			Decrypt();
			key_map_1.insert(make_pair(GetDecText(), possible_key1));
			if (counter == 2){
				key_map_2.insert(make_pair(GetDecText(), possible_key1));
			}
		}
		possible_key.clear();
		possible_key1.clear();
		str_key = "";
		

	}
	return key_map_1;
}

void DES_Cipher::PrintKey(vector<char> vect)
{
	for (int i = 0; i < vect.size(); i++){
		cout << vect[i];
	}
}


//compare two maps
void DES_Cipher::FindKeys(map<vector<char>, vector<char>> &enc_map, map<vector<char>, vector<char>> &dec_map)
{
	map<vector<char>, vector<char>>::iterator m,k;
	k = dec_map.begin();
	while (k!=dec_map.end())
	{
		m = enc_map.find(k->first);
		if (m != enc_map.end()){
			cout << "Possible pair of keys are: ";
			if (dec_map.size() == 1){
				PrintKey(k->second);
				cout << " and ";
				PrintKey(m->second);
			}
			else{
				PrintKey(m->second);
				cout << " and ";
				PrintKey(k->second);
				
			}
			cout << "\n";
		}
		k++;
	}
}


int _tmain(int argc, _TCHAR* argv[])
{
	char_bin_form key[14];
	vector<char> key1;
	vector<char> key2;
	vector<char> real_key1;
	vector<char> real_key2;
	vector<char> key_part1;
	vector<char> key_part2;
	char key_char[14];
	vector<char> bin_key;
	DES_Cipher des_ciph;
	int k_beg = 46;//start bit
	int delta_k = 18;//interval
	int k_end = 64;//last bit
	//so our interval from 46 bit to 63 bit. This means we need to guess 18 bits
	int bits_to_guess_in_first_key;
	int bits_to_guess_in_second_key;
	map<vector<char>, vector<char>> key_map1;
	map<vector<char>, vector<char>> key_map2;
	map<vector<char>, vector<char>> key_map3;
	map<vector<char>, vector<char>> key_map4;
	des_ciph.ReadFile("input.txt");
	des_ciph.GenerateCipherKey();
	real_key1 = des_ciph.GetCiphKey1();
	real_key2 = des_ciph.GetCiphKey2();
	des_ciph.EncryptDouble(real_key1, real_key2);
	for (int i = 0; i < 14; i++){
		if (i >=7){
			key_char[i] = real_key2[i-7];
		}
		else{
			key_char[i] = real_key1[i];
		}

	}
	bin_key=des_ciph.StringKeyRepr(key_char);
	/*
	for (int i = 0; i < 14; i++)
	{
		cout<<"Char representation: "<<key[i].ch<<"\n";
		cout << "Binary representation: " << key[i].a.seventh_bit << key[i].a.sixth_bit << key[i].a.fifth_bit << key[i].a.fourth_bit
										  << key[i].a.third_bit << key[i].a.second_bit << key[i].a.first_bit << key[i].a.null_bit;
		cout << "\n";

	}
	//PrintBinKey(bin_key);
	//at this point we know 46 initial bits in the first key
	//and 112-63=49 final bits of the second key
	//we need to fill two maps: the first map will contain 2^10 values
	//the second map will contain 2^8 values
	//the first map contains all pairs: C_k1(P) --- k1
	//the second map contains all pairs: P_k2(C) --- k2
	*/
	
	if (k_end <= 56 && k_beg<56){//if we need to guess only one key
		for (int i = 0; i < k_beg; i++){
			key_part1.push_back(bin_key[i]);
		}
		for (int i = k_end; i < 56; i++){
			key_part2.push_back(bin_key[i]);
		}
		key_map3=des_ciph.Map_BitsToGuessInsideOneKey(key_part1, key_part2, k_beg, k_end,ENC_MODE);
		key2.clear();
		for (int i = 56; i < 112; i++){//known second key
			key2.push_back(bin_key[i]);
		}
		bits_to_guess_in_second_key = 0;
		key_map4 = des_ciph.CreateSecondKeyMap(key2, bits_to_guess_in_second_key);
		des_ciph.FindKeys(key_map3, key_map4);
		des_ciph.PrintKey(real_key1);
		cout << "\n";
		des_ciph.PrintKey(real_key2);
		cout << "\n";
	}else if (k_beg>=56 && k_end>56){//if we need to guess only one key
		for (int i = 56; i < k_beg; i++){
			key_part1.push_back(bin_key[i]);
		}
		for (int i = k_end; i < 112; i++){
			key_part2.push_back(bin_key[i]);
		}
		key_map3 = des_ciph.Map_BitsToGuessInsideOneKey(key_part1, key_part2, k_beg, k_end,DEC_MODE);
		key1.clear();
		for (int i = 0; i < 56; i++){//known first key
			key1.push_back(bin_key[i]);
		}
		bits_to_guess_in_first_key = 0;
		key_map4 = des_ciph.CreateFirstKeyMap(key1, bits_to_guess_in_first_key);
		des_ciph.FindKeys(key_map3, key_map4);
		des_ciph.PrintKey(real_key1);
		cout << "\n";
		des_ciph.PrintKey(real_key2);
		cout << "\n";
	}
	else{
		for (int i = 0; i < k_beg; i++){
			key1.push_back(bin_key[i]);
		}
		des_ciph.PrintBinKey(key1);
		bits_to_guess_in_first_key = 56 - k_beg;
		des_ciph.PrintBinKey(key1);
		for (int i = k_end; i <bin_key.size(); i++){
			key2.push_back(bin_key[i]);
		}
		bits_to_guess_in_second_key = (k_end)-56;
		cout << "\n";
		des_ciph.PrintBinKey(key2);
		key_map1 = des_ciph.CreateFirstKeyMap(key1, bits_to_guess_in_first_key);
		key_map2 = des_ciph.CreateSecondKeyMap(key2, bits_to_guess_in_second_key);
		des_ciph.FindKeys(key_map1, key_map2);
		des_ciph.PrintKey(real_key1);
		cout << "\n";
		des_ciph.PrintKey(real_key2);
		cout << "\n";

	}
	return 0;
}

//каким образом можно обратиться к заданному биту? Нужно перевести в строку(вектор). Далее работать. 
