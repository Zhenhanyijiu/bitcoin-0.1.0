// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

class CTransaction;

enum
{
    SIGHASH_ALL = 1,
    SIGHASH_NONE = 2,
    SIGHASH_SINGLE = 3,
    SIGHASH_ANYONECANPAY = 0x80,
};



enum opcodetype//定义操作码类型
{
    // push value
    OP_0=0,
    OP_FALSE=OP_0,
    OP_PUSHDATA1=76,
    OP_PUSHDATA2,
    OP_PUSHDATA4,
    OP_1NEGATE,
    OP_RESERVED,
    OP_1,
    OP_TRUE=OP_1,
    OP_2,
    OP_3,
    OP_4,
    OP_5,
    OP_6,
    OP_7,
    OP_8,
    OP_9,
    OP_10,
    OP_11,
    OP_12,
    OP_13,
    OP_14,
    OP_15,
    OP_16,

    // control
    OP_NOP,
    OP_VER,
    OP_IF,
    OP_NOTIF,
    OP_VERIF,
    OP_VERNOTIF,
    OP_ELSE,
    OP_ENDIF,
    OP_VERIFY,
    OP_RETURN,

    // stack ops
    OP_TOALTSTACK,
    OP_FROMALTSTACK,
    OP_2DROP,
    OP_2DUP,
    OP_3DUP,
    OP_2OVER,
    OP_2ROT,
    OP_2SWAP,
    OP_IFDUP,
    OP_DEPTH,
    OP_DROP,
    OP_DUP,
    OP_NIP,
    OP_OVER,
    OP_PICK,
    OP_ROLL,
    OP_ROT,
    OP_SWAP,
    OP_TUCK,

    // splice ops
    OP_CAT,
    OP_SUBSTR,
    OP_LEFT,
    OP_RIGHT,
    OP_SIZE,

    // bit logic
    OP_INVERT,
    OP_AND,
    OP_OR,
    OP_XOR,
    OP_EQUAL,
    OP_EQUALVERIFY,
    OP_RESERVED1,
    OP_RESERVED2,

    // numeric
    OP_1ADD,
    OP_1SUB,
    OP_2MUL,
    OP_2DIV,
    OP_NEGATE,
    OP_ABS,
    OP_NOT,
    OP_0NOTEQUAL,

    OP_ADD,
    OP_SUB,
    OP_MUL,
    OP_DIV,
    OP_MOD,
    OP_LSHIFT,
    OP_RSHIFT,

    OP_BOOLAND,
    OP_BOOLOR,
    OP_NUMEQUAL,
    OP_NUMEQUALVERIFY,
    OP_NUMNOTEQUAL,
    OP_LESSTHAN,
    OP_GREATERTHAN,
    OP_LESSTHANOREQUAL,
    OP_GREATERTHANOREQUAL,
    OP_MIN,
    OP_MAX,

    OP_WITHIN,

    // crypto
    OP_RIPEMD160,
    OP_SHA1,
    OP_SHA256,
    OP_HASH160,
    OP_HASH256,
    OP_CODESEPARATOR,
    OP_CHECKSIG,
    OP_CHECKSIGVERIFY,
    OP_CHECKMULTISIG,
    OP_CHECKMULTISIGVERIFY,


    // multi-byte opcodes
    OP_SINGLEBYTE_END = 0xF0,
    OP_DOUBLEBYTE_BEGIN = 0xF000,

    // template matching params
    OP_PUBKEY,//模板匹配参数，代表公钥域
    OP_PUBKEYHASH,



    OP_INVALIDOPCODE = 0xFFFF,
};

inline const char* GetOpName(opcodetype opcode)//返回对应操作码类型的
{											   //字符串名字
    switch (opcode)
    {
    // push value
    case OP_0                      : return "0";
    case OP_PUSHDATA1              : return "OP_PUSHDATA1";
    case OP_PUSHDATA2              : return "OP_PUSHDATA2";
    case OP_PUSHDATA4              : return "OP_PUSHDATA4";
    case OP_1NEGATE                : return "-1";
    case OP_RESERVED               : return "OP_RESERVED";
    case OP_1                      : return "1";
    case OP_2                      : return "2";
    case OP_3                      : return "3";
    case OP_4                      : return "4";
    case OP_5                      : return "5";
    case OP_6                      : return "6";
    case OP_7                      : return "7";
    case OP_8                      : return "8";
    case OP_9                      : return "9";
    case OP_10                     : return "10";
    case OP_11                     : return "11";
    case OP_12                     : return "12";
    case OP_13                     : return "13";
    case OP_14                     : return "14";
    case OP_15                     : return "15";
    case OP_16                     : return "16";

    // control
    case OP_NOP                    : return "OP_NOP";
    case OP_VER                    : return "OP_VER";
    case OP_IF                     : return "OP_IF";
    case OP_NOTIF                  : return "OP_NOTIF";
    case OP_VERIF                  : return "OP_VERIF";
    case OP_VERNOTIF               : return "OP_VERNOTIF";
    case OP_ELSE                   : return "OP_ELSE";
    case OP_ENDIF                  : return "OP_ENDIF";
    case OP_VERIFY                 : return "OP_VERIFY";
    case OP_RETURN                 : return "OP_RETURN";

    // stack ops
    case OP_TOALTSTACK             : return "OP_TOALTSTACK";
    case OP_FROMALTSTACK           : return "OP_FROMALTSTACK";
    case OP_2DROP                  : return "OP_2DROP";
    case OP_2DUP                   : return "OP_2DUP";
    case OP_3DUP                   : return "OP_3DUP";
    case OP_2OVER                  : return "OP_2OVER";
    case OP_2ROT                   : return "OP_2ROT";
    case OP_2SWAP                  : return "OP_2SWAP";
    case OP_IFDUP                  : return "OP_IFDUP";
    case OP_DEPTH                  : return "OP_DEPTH";
    case OP_DROP                   : return "OP_DROP";
    case OP_DUP                    : return "OP_DUP";
    case OP_NIP                    : return "OP_NIP";
    case OP_OVER                   : return "OP_OVER";
    case OP_PICK                   : return "OP_PICK";
    case OP_ROLL                   : return "OP_ROLL";
    case OP_ROT                    : return "OP_ROT";
    case OP_SWAP                   : return "OP_SWAP";
    case OP_TUCK                   : return "OP_TUCK";

    // splice ops
    case OP_CAT                    : return "OP_CAT";
    case OP_SUBSTR                 : return "OP_SUBSTR";
    case OP_LEFT                   : return "OP_LEFT";
    case OP_RIGHT                  : return "OP_RIGHT";
    case OP_SIZE                   : return "OP_SIZE";

    // bit logic
    case OP_INVERT                 : return "OP_INVERT";
    case OP_AND                    : return "OP_AND";
    case OP_OR                     : return "OP_OR";
    case OP_XOR                    : return "OP_XOR";
    case OP_EQUAL                  : return "OP_EQUAL";
    case OP_EQUALVERIFY            : return "OP_EQUALVERIFY";
    case OP_RESERVED1              : return "OP_RESERVED1";
    case OP_RESERVED2              : return "OP_RESERVED2";

    // numeric
    case OP_1ADD                   : return "OP_1ADD";
    case OP_1SUB                   : return "OP_1SUB";
    case OP_2MUL                   : return "OP_2MUL";
    case OP_2DIV                   : return "OP_2DIV";
    case OP_NEGATE                 : return "OP_NEGATE";
    case OP_ABS                    : return "OP_ABS";
    case OP_NOT                    : return "OP_NOT";
    case OP_0NOTEQUAL              : return "OP_0NOTEQUAL";
    case OP_ADD                    : return "OP_ADD";
    case OP_SUB                    : return "OP_SUB";
    case OP_MUL                    : return "OP_MUL";
    case OP_DIV                    : return "OP_DIV";
    case OP_MOD                    : return "OP_MOD";
    case OP_LSHIFT                 : return "OP_LSHIFT";
    case OP_RSHIFT                 : return "OP_RSHIFT";
    case OP_BOOLAND                : return "OP_BOOLAND";
    case OP_BOOLOR                 : return "OP_BOOLOR";
    case OP_NUMEQUAL               : return "OP_NUMEQUAL";
    case OP_NUMEQUALVERIFY         : return "OP_NUMEQUALVERIFY";
    case OP_NUMNOTEQUAL            : return "OP_NUMNOTEQUAL";
    case OP_LESSTHAN               : return "OP_LESSTHAN";
    case OP_GREATERTHAN            : return "OP_GREATERTHAN";
    case OP_LESSTHANOREQUAL        : return "OP_LESSTHANOREQUAL";
    case OP_GREATERTHANOREQUAL     : return "OP_GREATERTHANOREQUAL";
    case OP_MIN                    : return "OP_MIN";
    case OP_MAX                    : return "OP_MAX";
    case OP_WITHIN                 : return "OP_WITHIN";

    // crypto
    case OP_RIPEMD160              : return "OP_RIPEMD160";
    case OP_SHA1                   : return "OP_SHA1";
    case OP_SHA256                 : return "OP_SHA256";
    case OP_HASH160                : return "OP_HASH160";
    case OP_HASH256                : return "OP_HASH256";
    case OP_CODESEPARATOR          : return "OP_CODESEPARATOR";
    case OP_CHECKSIG               : return "OP_CHECKSIG";
    case OP_CHECKSIGVERIFY         : return "OP_CHECKSIGVERIFY";
    case OP_CHECKMULTISIG          : return "OP_CHECKMULTISIG";
    case OP_CHECKMULTISIGVERIFY    : return "OP_CHECKMULTISIGVERIFY";



    // multi-byte opcodes
    case OP_SINGLEBYTE_END         : return "OP_SINGLEBYTE_END";
    case OP_DOUBLEBYTE_BEGIN       : return "OP_DOUBLEBYTE_BEGIN";
    case OP_PUBKEY                 : return "OP_PUBKEY";
    case OP_PUBKEYHASH             : return "OP_PUBKEYHASH";



    case OP_INVALIDOPCODE          : return "OP_INVALIDOPCODE";
    default:
        return "UNKNOWN_OPCODE";
    }
};




inline string ValueString(const vector<unsigned char>& vch)//如果向量不超过4个字节
{											//以整数的形式返回，否则输出16进制字符串形式
    if (vch.size() <= 4)
        return strprintf("%d", CBigNum(vch).getint());
    else
        return HexNumStr(vch.begin(), vch.end());
        //return string("(") + HexStr(vch.begin(), vch.end()) + string(")");
}

inline string StackString(const vector<vector<unsigned char> >& vStack)
{
    string str;
    foreach(const vector<unsigned char>& vch, vStack)//遍历栈，输出栈中元素
    {												//并用空格隔开
        if (!str.empty())
            str += " ";
        str += ValueString(vch);
    }
    return str;
}



class CScript : public vector<unsigned char>//定义脚本类型，继承于字符向量类型
{
protected:
    CScript& push_int64(int64 n)//将一个整数n以字符的形式压入字符向量
    {
        if (n == -1 || (n >= 1 && n <= 16))//n=-1,1~16
        {
            push_back(n + (OP_1 - 1));//OP_1=0x51=81,将79,81~96压入脚本向量的末尾
        }
        else
        {
            CBigNum bn(n);
            *this << bn.getvch();//返回一个大数对应的字符向量并压入脚本向量的末尾
        }
        return (*this);
    }
	//无符号的情况
    CScript& push_uint64(uint64 n)
    {
        if (n == -1 || (n >= 1 && n <= 16))
        {
            push_back(n + (OP_1 - 1));
        }
        else
        {
            CBigNum bn(n);
            *this << bn.getvch();
        }
        return (*this);
    }

public:
    CScript() { }//构造一个空的脚本
    CScript(const CScript& b) : vector<unsigned char>(b.begin(), b.end()) { }
    CScript(const_iterator pbegin, const_iterator pend) : vector<unsigned char>(pbegin, pend) { }
#ifndef _MSC_VER
    CScript(const unsigned char* pbegin, const unsigned char* pend) : vector<unsigned char>(pbegin, pend) { }
#endif

    CScript& operator+=(const CScript& b)//将脚本b接连到本身脚本上并返回
    {
        insert(end(), b.begin(), b.end());
        return *this;
    }

    friend CScript operator+(const CScript& a, const CScript& b)//两个脚本相加
    {
        CScript ret = a;
        ret += b;
        return (ret);
    }


    explicit CScript(char b)           { operator<<(b); }
    explicit CScript(short b)          { operator<<(b); }
    explicit CScript(int b)            { operator<<(b); }
    explicit CScript(long b)           { operator<<(b); }
    explicit CScript(int64 b)          { operator<<(b); }
    explicit CScript(unsigned char b)  { operator<<(b); }
    explicit CScript(unsigned int b)   { operator<<(b); }
    explicit CScript(unsigned short b) { operator<<(b); }
    explicit CScript(unsigned long b)  { operator<<(b); }
    explicit CScript(uint64 b)         { operator<<(b); }

    explicit CScript(opcodetype b)     { operator<<(b); }
    explicit CScript(const uint256& b) { operator<<(b); }
    explicit CScript(const CBigNum& b) { operator<<(b); }
    explicit CScript(const vector<unsigned char>& b) { operator<<(b); }

	//运算符的重载
    CScript& operator<<(char b)           { return (push_int64(b)); }
    CScript& operator<<(short b)          { return (push_int64(b)); }
    CScript& operator<<(int b)            { return (push_int64(b)); }
    CScript& operator<<(long b)           { return (push_int64(b)); }
    CScript& operator<<(int64 b)          { return (push_int64(b)); }
    CScript& operator<<(unsigned char b)  { return (push_uint64(b)); }
    CScript& operator<<(unsigned int b)   { return (push_uint64(b)); }
    CScript& operator<<(unsigned short b) { return (push_uint64(b)); }
    CScript& operator<<(unsigned long b)  { return (push_uint64(b)); }
    CScript& operator<<(uint64 b)         { return (push_uint64(b)); }

    CScript& operator<<(opcodetype opcode)
    {
        if (opcode <= OP_SINGLEBYTE_END)
        {
            insert(end(), (unsigned char)opcode);
        }
        else
        {
            assert(opcode >= OP_DOUBLEBYTE_BEGIN);
            insert(end(), (unsigned char)(opcode >> 8));
            insert(end(), (unsigned char)(opcode & 0xFF));
        }
        return (*this);
    }

    CScript& operator<<(const uint160& b)
    {
        insert(end(), sizeof(b));
        insert(end(), (unsigned char*)&b, (unsigned char*)&b + sizeof(b));
        return (*this);
    }

    CScript& operator<<(const uint256& b)
    {
        insert(end(), sizeof(b));
        insert(end(), (unsigned char*)&b, (unsigned char*)&b + sizeof(b));
        return (*this);
    }

    CScript& operator<<(const CBigNum& b)
    {
        *this << b.getvch();
        return (*this);
    }

    CScript& operator<<(const vector<unsigned char>& b)//以向量b构造脚本
    {
        if (b.size() < OP_PUSHDATA1)//b的字节长度小于OP_PUSHDATA=76,
        {
            insert(end(), (unsigned char)b.size());//将b的字节大小压入脚本
        }
        else if (b.size() <= 0xff)//字节大小小于0xff,大于等于76,
        {
            insert(end(), OP_PUSHDATA1);//将操作码OP_PUSHDATA1压入脚本中
            insert(end(), (unsigned char)b.size());//再将b的字节大小压入脚本中
        }
        else
        {
            insert(end(), OP_PUSHDATA2);//将操作码OP_PUSHDATA2压入脚本中
            unsigned short nSize = b.size();//获取b的字节大小
            insert(end(), (unsigned char*)&nSize, (unsigned char*)&nSize + sizeof(nSize));//将整数值压入到脚本中,
        }																				//按照变量的地址及整数所占的字节数
        insert(end(), b.begin(), b.end());
        return (*this);
    }

    CScript& operator<<(const CScript& b)
    {
        // I'm not sure if this should push the script or concatenate scripts.
        // If there's ever a use for pushing a script onto a script, delete this member fn
        assert(("warning: pushing a CScript onto a CScript with << is probably not intended, use + to concatenate", false));
        return (*this);
    }


    bool GetOp(iterator& pc, opcodetype& opcodeRet, vector<unsigned char>& vchRet)
    {
         // This is why people hate C++
         const_iterator pc2 = pc;//将pc的赋值给新的迭代器
         bool fRet = GetOp(pc2, opcodeRet, vchRet);//调用常成员函数，返回操作码
         pc = begin() + (pc2 - begin());//返回当前的pc
         return fRet;
    }

	/*****************************************************
	***数据类的序列化(<<操作符)进入脚本都会被OP_PUSHDATA1,
	***OP_PUSHDATA2,OP_PUSHDATA4操作符所标明，指明这是一个
	***数据
	******************************************************/
    bool GetOp(const_iterator& pc, opcodetype& opcodeRet, vector<unsigned char>& vchRet) const
    {
        opcodeRet = OP_INVALIDOPCODE;//opcodeRet被赋予无效操作码
        vchRet.clear();//清空字符向量vchRet
        if (pc >= end())//pc为const_iterator迭代器，本身可以自增，但其指向的值是不可以改变的，如果pc指向end(),返回错误
            return false;

        // Read instruction
        unsigned int opcode = *pc++;//定义一个opcode初始化为*pc（pc指向的值），然后pc加1
        if (opcode >= OP_SINGLEBYTE_END)//如果opcode的值>=OP_SINGLEBYTE_END(240)
        {
            if (pc + 1 > end())//如果此时pc指向end()，则返回错误！
                return false;
            opcode <<= 8;   //opcode 左移8位，如0xF0->0xF000,0xFF->0xFF00
            opcode |= *pc++;//取出此时pc指向的值，按位或上opcode,是为了取出最后几个双字节操作码,pc自增1
        }

        // Immediate operand(立即数)
        if (opcode <= OP_PUSHDATA4) //如果opcode小于240，单字节操作码,并且是前面几个指令，小于等于78
        {
            unsigned int nSize = opcode;//定义一个字节大小的变量nSize,并被赋值opcode
            if (opcode == OP_PUSHDATA1)//操作码等于76，表示再取出一个字节,作为新的字节大小
            {
                if (pc + 1 > end())  //如果此时pc指向end，那么返回错误
                    return false;
                nSize = *pc++;        //取出此时pc指向的值，并赋值给 nSize,pc自增1
            }
            else if (opcode == OP_PUSHDATA2)//操作码等于77，表示再取出两个字节，作为新的字节大小
            {
                if (pc + 2 > end())  //如果end与pc之间的元素个数小于2，出错！
                    return false;
                nSize = 0;           //nSize赋值为0
                memcpy(&nSize, &pc[0], 2);//读取两个字节存到变量nSize中
                pc += 2;//pc 移动2个字节
            }
            else if (opcode == OP_PUSHDATA4)//操作等于78，表示再读取4个字节，作为新的字节大小
            {
                if (pc + 4 > end())    //不够4个字节，出错！
                    return false;
                memcpy(&nSize, &pc[0], 4);//读取4个字节存到变量nSize中
                pc += 4;   //pc 移动4个字节
            }
			//其他值1~75
            if (pc + nSize > end())//不够nSize个字节，出错！
                return false;
            vchRet.assign(pc, pc + nSize);//读取nSize字节，用于替换向量vchRet的内容
            pc += nSize;
        }
		//79~240之间的操作码，直返回操作码，vchRet不做任何处理

        opcodeRet = (opcodetype)opcode;//将opcode表示的操作码赋给opcodeRet返回
        return true;
    }


    void FindAndDelete(const CScript& b)//参数为脚本类对象b，功能：在本身对象中查找并删除对象b
    {
        iterator pc = begin();//pc首先指向本身对象的开始处
        opcodetype opcode;//定义一个操作码变量
        vector<unsigned char> vchPushValue;//定义一个字符向量
        int count = 0;//计数器
        do
        {		//本身对象字节大小不能小于对象b的字节大小
				//memcmp函数：比较&pc[0]和&b[0]前b.size()个字符，若相等返回0,即找到了对象b
            while (end() - pc >= b.size() && memcmp(&pc[0], &b[0], b.size()) == 0)
            {
                erase(pc, pc + b.size());//在本身对象中删除对象b，删除区间[pc,pc+b.size())的元素
                count++;//计数器加1
            }
        }
        while (GetOp(pc, opcode, vchPushValue));//读取一个操作码并更新pc，从新的pc处开始继续查找
        //printf("FindAndDeleted deleted %d items\n", count); // debug
    }


    void PrintHex() const
    {
        printf("CScript(%s)\n", HexStr(begin(), end()).c_str());
    }

    string ToString() const
    {
        string str;
        opcodetype opcode;
        vector<unsigned char> vch;
        const_iterator it = begin();
        while (GetOp(it, opcode, vch))//返回操作码
        {
            if (!str.empty())
                str += " ";
            if (opcode <= OP_PUSHDATA4)//操作码小于等于OP_PUSHDATA4,78,并将返回的字符向量接连在一起
                str += ValueString(vch);
            else
                str += GetOpName(opcode);//接连对应操作码的字符串名字
        }
        return str;
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};








bool EvalScript(const CScript& script, const CTransaction& txTo, unsigned int nIn, int nHashType=0,
                vector<vector<unsigned char> >* pvStackRet=NULL);
uint256 SignatureHash(CScript scriptCode, const CTransaction& txTo, unsigned int nIn, int nHashType);
bool IsMine(const CScript& scriptPubKey);
bool ExtractPubKey(const CScript& scriptPubKey, bool fMineOnly, vector<unsigned char>& vchPubKeyRet);
bool ExtractHash160(const CScript& scriptPubKey, uint160& hash160Ret);
bool SignSignature(const CTransaction& txFrom, CTransaction& txTo, unsigned int nIn, int nHashType=SIGHASH_ALL, CScript scriptPrereq=CScript());
bool VerifySignature(const CTransaction& txFrom, const CTransaction& txTo, unsigned int nIn, int nHashType=0);
