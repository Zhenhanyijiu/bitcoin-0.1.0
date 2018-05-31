// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include "headers.h"

bool CheckSig(vector<unsigned char> vchSig, vector<unsigned char> vchPubKey, CScript scriptCode, const CTransaction& txTo, unsigned int nIn, int nHashType);



typedef vector<unsigned char> valtype;//值类型向量类型，可以理解为里面存的是数据
static const valtype vchFalse(0);
static const valtype vchZero(0);
static const valtype vchTrue(1, 1);
static const CBigNum bnZero(0);
static const CBigNum bnOne(1);
static const CBigNum bnFalse(0);
static const CBigNum bnTrue(1);


bool CastToBool(const valtype& vch)//值类型向量表示的大数不为0，返回true，否则返回false
{
    return (CBigNum(vch) != bnZero);
}

void MakeSameSize(valtype& vch1, valtype& vch2)
{
    // Lengthen the shorter one
    if (vch1.size() < vch2.size())
        vch1.resize(vch2.size(), 0);//重置vch1的大小为vch2的大小，多出的赋值为0
    if (vch2.size() < vch1.size())
        vch2.resize(vch1.size(), 0);//重置vch2的大小为vch1的大小，多出的赋值为0
}



//
// Script is a stack machine (like Forth) that evaluates a predicate
// returning a bool indicating valid or not.  There are no loops.
//
#define stacktop(i)  (stack.at(stack.size()+(i)))
#define altstacktop(i)  (altstack.at(altstack.size()+(i)))

//执行Script的函数
bool EvalScript(const CScript& script, const CTransaction& txTo, unsigned int nIn, int nHashType,
                vector<vector<unsigned char> >* pvStackRet)
{
    CAutoBN_CTX pctx;
    CScript::const_iterator pc = script.begin();
    CScript::const_iterator pend = script.end();
    CScript::const_iterator pbegincodehash = script.begin();
    vector<bool> vfExec;//这是一个暂时的记录，栈中执行if判断结果的地方
    vector<valtype> stack;//栈就是这一个，而valtype就是一个字符向量类型
    vector<valtype> altstack;
    if (pvStackRet)
        pvStackRet->clear();


    while (pc < pend)
    {
        bool fExec = !count(vfExec.begin(), vfExec.end(), false);

        //
        // Read instruction
        //
        opcodetype opcode;
        valtype vchPushValue;
        if (!script.GetOp(pc, opcode, vchPushValue))
            return false;

        if (fExec && opcode <= OP_PUSHDATA4)
            stack.push_back(vchPushValue);
        else if (fExec || (OP_IF <= opcode && opcode <= OP_ENDIF))
        switch (opcode)
        {
            //
            // Push value
            //
            case OP_1NEGATE:
            case OP_1:
            case OP_2:
            case OP_3:
            case OP_4:
            case OP_5:
            case OP_6:
            case OP_7:
            case OP_8:
            case OP_9:
            case OP_10:
            case OP_11:
            case OP_12:
            case OP_13:
            case OP_14:
            case OP_15:
            case OP_16:
            {
                // ( -- value)
                CBigNum bn((int)opcode - (int)(OP_1 - 1));
                stack.push_back(bn.getvch());
            }
            break;


            //
            // Control
            //
            case OP_NOP:
            break;

            case OP_VER:
            {
                CBigNum bn(VERSION);
                stack.push_back(bn.getvch());
            }
            break;

            case OP_IF:
            case OP_NOTIF:
            case OP_VERIF:
            case OP_VERNOTIF:
            {
                // <expression> if [statements] [else [statements]] endif
                bool fValue = false;
                if (fExec)
                {
                    if (stack.size() < 1)
                        return false;
                    valtype& vch = stacktop(-1);
                    if (opcode == OP_VERIF || opcode == OP_VERNOTIF)
                        fValue = (CBigNum(VERSION) >= CBigNum(vch));
                    else
                        fValue = CastToBool(vch);
                    if (opcode == OP_NOTIF || opcode == OP_VERNOTIF)
                        fValue = !fValue;
                    stack.pop_back();
                }
                vfExec.push_back(fValue);
            }
            break;

            case OP_ELSE:
            {
                if (vfExec.empty())
                    return false;
                vfExec.back() = !vfExec.back();
            }
            break;

            case OP_ENDIF:
            {
                if (vfExec.empty())
                    return false;
                vfExec.pop_back();
            }
            break;

            case OP_VERIFY:
            {
                // (true -- ) or
                // (false -- false) and return
                if (stack.size() < 1)
                    return false;
                bool fValue = CastToBool(stacktop(-1));
                if (fValue)
                    stack.pop_back();
                else
                    pc = pend;
            }
            break;

            case OP_RETURN:
            {
                pc = pend;
            }
            break;


            //
            // Stack ops
            //
            case OP_TOALTSTACK:
            {
                if (stack.size() < 1)
                    return false;
                altstack.push_back(stacktop(-1));
                stack.pop_back();
            }
            break;

            case OP_FROMALTSTACK:
            {
                if (altstack.size() < 1)
                    return false;
                stack.push_back(altstacktop(-1));
                altstack.pop_back();
            }
            break;

            case OP_2DROP:
            {
                // (x1 x2 -- )
                stack.pop_back();
                stack.pop_back();
            }
            break;

            case OP_2DUP:
            {
                // (x1 x2 -- x1 x2 x1 x2)
                if (stack.size() < 2)
                    return false;
                valtype vch1 = stacktop(-2);
                valtype vch2 = stacktop(-1);
                stack.push_back(vch1);
                stack.push_back(vch2);
            }
            break;

            case OP_3DUP:
            {
                // (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
                if (stack.size() < 3)
                    return false;
                valtype vch1 = stacktop(-3);
                valtype vch2 = stacktop(-2);
                valtype vch3 = stacktop(-1);
                stack.push_back(vch1);
                stack.push_back(vch2);
                stack.push_back(vch3);
            }
            break;

            case OP_2OVER:
            {
                // (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
                if (stack.size() < 4)
                    return false;
                valtype vch1 = stacktop(-4);
                valtype vch2 = stacktop(-3);
                stack.push_back(vch1);
                stack.push_back(vch2);
            }
            break;

            case OP_2ROT:
            {
                // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
                if (stack.size() < 6)
                    return false;
                valtype vch1 = stacktop(-6);
                valtype vch2 = stacktop(-5);
                stack.erase(stack.end()-6, stack.end()-4);
                stack.push_back(vch1);
                stack.push_back(vch2);
            }
            break;

            case OP_2SWAP:
            {
                // (x1 x2 x3 x4 -- x3 x4 x1 x2)
                if (stack.size() < 4)
                    return false;
                swap(stacktop(-4), stacktop(-2));
                swap(stacktop(-3), stacktop(-1));
            }
            break;

            case OP_IFDUP:
            {
                // (x - 0 | x x)
                if (stack.size() < 1)
                    return false;
                valtype vch = stacktop(-1);
                if (CastToBool(vch))
                    stack.push_back(vch);
            }
            break;

            case OP_DEPTH:
            {
                // -- stacksize
                CBigNum bn(stack.size());
                stack.push_back(bn.getvch());
            }
            break;

            case OP_DROP:
            {
                // (x -- )
                if (stack.size() < 1)
                    return false;
                stack.pop_back();
            }
            break;

            case OP_DUP:
            {
                // (x -- x x)
                if (stack.size() < 1)
                    return false;
                valtype vch = stacktop(-1);
                stack.push_back(vch);
            }
            break;

            case OP_NIP:
            {
                // (x1 x2 -- x2)
                if (stack.size() < 2)
                    return false;
                stack.erase(stack.end() - 2);
            }
            break;

            case OP_OVER:
            {
                // (x1 x2 -- x1 x2 x1)
                if (stack.size() < 2)
                    return false;
                valtype vch = stacktop(-2);
                stack.push_back(vch);
            }
            break;

            case OP_PICK:
            case OP_ROLL:
            {
                // (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
                // (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
                if (stack.size() < 2)
                    return false;
                int n = CBigNum(stacktop(-1)).getint();
                stack.pop_back();
                if (n < 0 || n >= stack.size())
                    return false;
                valtype vch = stacktop(-n-1);
                if (opcode == OP_ROLL)
                    stack.erase(stack.end()-n-1);
                stack.push_back(vch);
            }
            break;

            case OP_ROT:
            {
                // (x1 x2 x3 -- x2 x3 x1)
                //  x2 x1 x3  after first swap
                //  x2 x3 x1  after second swap
                if (stack.size() < 3)
                    return false;
                swap(stacktop(-3), stacktop(-2));
                swap(stacktop(-2), stacktop(-1));
            }
            break;

            case OP_SWAP:
            {
                // (x1 x2 -- x2 x1)
                if (stack.size() < 2)
                    return false;
                swap(stacktop(-2), stacktop(-1));
            }
            break;

            case OP_TUCK:
            {
                // (x1 x2 -- x2 x1 x2)
                if (stack.size() < 2)
                    return false;
                valtype vch = stacktop(-1);
                stack.insert(stack.end()-2, vch);
            }
            break;


            //
            // Splice ops
            //
            case OP_CAT:
            {
                // (x1 x2 -- out)
                if (stack.size() < 2)
                    return false;
                valtype& vch1 = stacktop(-2);
                valtype& vch2 = stacktop(-1);
                vch1.insert(vch1.end(), vch2.begin(), vch2.end());
                stack.pop_back();
            }
            break;

            case OP_SUBSTR:
            {
                // (in begin size -- out)
                if (stack.size() < 3)
                    return false;
                valtype& vch = stacktop(-3);
                int nBegin = CBigNum(stacktop(-2)).getint();
                int nEnd = nBegin + CBigNum(stacktop(-1)).getint();
                if (nBegin < 0 || nEnd < nBegin)
                    return false;
                if (nBegin > vch.size())
                    nBegin = vch.size();
                if (nEnd > vch.size())
                    nEnd = vch.size();
                vch.erase(vch.begin() + nEnd, vch.end());
                vch.erase(vch.begin(), vch.begin() + nBegin);
                stack.pop_back();
                stack.pop_back();
            }
            break;

            case OP_LEFT:
            case OP_RIGHT:
            {
                // (in size -- out)
                if (stack.size() < 2)
                    return false;
                valtype& vch = stacktop(-2);
                int nSize = CBigNum(stacktop(-1)).getint();
                if (nSize < 0)
                    return false;
                if (nSize > vch.size())
                    nSize = vch.size();
                if (opcode == OP_LEFT)
                    vch.erase(vch.begin() + nSize, vch.end());
                else
                    vch.erase(vch.begin(), vch.end() - nSize);
                stack.pop_back();
            }
            break;

            case OP_SIZE:
            {
                // (in -- in size)
                if (stack.size() < 1)
                    return false;
                CBigNum bn(stacktop(-1).size());
                stack.push_back(bn.getvch());
            }
            break;


            //
            // Bitwise logic
            //
            case OP_INVERT:
            {
                // (in - out)
                if (stack.size() < 1)
                    return false;
                valtype& vch = stacktop(-1);
                for (int i = 0; i < vch.size(); i++)
                    vch[i] = ~vch[i];
            }
            break;

            case OP_AND:
            case OP_OR:
            case OP_XOR:
            {
                // (x1 x2 - out)
                if (stack.size() < 2)
                    return false;
                valtype& vch1 = stacktop(-2);
                valtype& vch2 = stacktop(-1);
                MakeSameSize(vch1, vch2);
                if (opcode == OP_AND)
                {
                    for (int i = 0; i < vch1.size(); i++)
                        vch1[i] &= vch2[i];
                }
                else if (opcode == OP_OR)
                {
                    for (int i = 0; i < vch1.size(); i++)
                        vch1[i] |= vch2[i];
                }
                else if (opcode == OP_XOR)
                {
                    for (int i = 0; i < vch1.size(); i++)
                        vch1[i] ^= vch2[i];
                }
                stack.pop_back();
            }
            break;

            case OP_EQUAL:
            case OP_EQUALVERIFY:
            //case OP_NOTEQUAL: // use OP_NUMNOTEQUAL
            {
                // (x1 x2 - bool)
                if (stack.size() < 2)
                    return false;
                valtype& vch1 = stacktop(-2);
                valtype& vch2 = stacktop(-1);
                bool fEqual = (vch1 == vch2);
                // OP_NOTEQUAL is disabled because it would be too easy to say
                // something like n != 1 and have some wiseguy pass in 1 with extra
                // zero bytes after it (numerically, 0x01 == 0x0001 == 0x000001)
                //if (opcode == OP_NOTEQUAL)
                //    fEqual = !fEqual;
                stack.pop_back();
                stack.pop_back();
                stack.push_back(fEqual ? vchTrue : vchFalse);
                if (opcode == OP_EQUALVERIFY)
                {
                    if (fEqual)
                        stack.pop_back();
                    else
                        pc = pend;
                }
            }
            break;


            //
            // Numeric
            //
            case OP_1ADD:
            case OP_1SUB:
            case OP_2MUL:
            case OP_2DIV:
            case OP_NEGATE:
            case OP_ABS:
            case OP_NOT:
            case OP_0NOTEQUAL:
            {
                // (in -- out)
                if (stack.size() < 1)
                    return false;
                CBigNum bn(stacktop(-1));
                switch (opcode)
                {
                case OP_1ADD:       bn += bnOne; break;
                case OP_1SUB:       bn -= bnOne; break;
                case OP_2MUL:       bn <<= 1; break;
                case OP_2DIV:       bn >>= 1; break;
                case OP_NEGATE:     bn = -bn; break;
                case OP_ABS:        if (bn < bnZero) bn = -bn; break;
                case OP_NOT:        bn = (bn == bnZero); break;
                case OP_0NOTEQUAL:  bn = (bn != bnZero); break;
                }
                stack.pop_back();
                stack.push_back(bn.getvch());
            }
            break;

            case OP_ADD:
            case OP_SUB:
            case OP_MUL:
            case OP_DIV:
            case OP_MOD:
            case OP_LSHIFT:
            case OP_RSHIFT:
            case OP_BOOLAND:
            case OP_BOOLOR:
            case OP_NUMEQUAL:
            case OP_NUMEQUALVERIFY:
            case OP_NUMNOTEQUAL:
            case OP_LESSTHAN:
            case OP_GREATERTHAN:
            case OP_LESSTHANOREQUAL:
            case OP_GREATERTHANOREQUAL:
            case OP_MIN:
            case OP_MAX:
            {
                // (x1 x2 -- out)
                if (stack.size() < 2)
                    return false;
                CBigNum bn1(stacktop(-2));
                CBigNum bn2(stacktop(-1));
                CBigNum bn;
                switch (opcode)
                {
                case OP_ADD:
                    bn = bn1 + bn2;
                    break;

                case OP_SUB:
                    bn = bn1 - bn2;
                    break;

                case OP_MUL:
                    if (!BN_mul(&bn, &bn1, &bn2, pctx))
                        return false;
                    break;

                case OP_DIV:
                    if (!BN_div(&bn, NULL, &bn1, &bn2, pctx))
                        return false;
                    break;

                case OP_MOD:
                    if (!BN_mod(&bn, &bn1, &bn2, pctx))
                        return false;
                    break;

                case OP_LSHIFT:
                    if (bn2 < bnZero)
                        return false;
                    bn = bn1 << bn2.getulong();
                    break;

                case OP_RSHIFT:
                    if (bn2 < bnZero)
                        return false;
                    bn = bn1 >> bn2.getulong();
                    break;

                case OP_BOOLAND:             bn = (bn1 != bnZero && bn2 != bnZero); break;
                case OP_BOOLOR:              bn = (bn1 != bnZero || bn2 != bnZero); break;
                case OP_NUMEQUAL:            bn = (bn1 == bn2); break;
                case OP_NUMEQUALVERIFY:      bn = (bn1 == bn2); break;
                case OP_NUMNOTEQUAL:         bn = (bn1 != bn2); break;
                case OP_LESSTHAN:            bn = (bn1 < bn2); break;
                case OP_GREATERTHAN:         bn = (bn1 > bn2); break;
                case OP_LESSTHANOREQUAL:     bn = (bn1 <= bn2); break;
                case OP_GREATERTHANOREQUAL:  bn = (bn1 >= bn2); break;
                case OP_MIN:                 bn = (bn1 < bn2 ? bn1 : bn2); break;
                case OP_MAX:                 bn = (bn1 > bn2 ? bn1 : bn2); break;
                }
                stack.pop_back();
                stack.pop_back();
                stack.push_back(bn.getvch());

                if (opcode == OP_NUMEQUALVERIFY)
                {
                    if (CastToBool(stacktop(-1)))
                        stack.pop_back();
                    else
                        pc = pend;
                }
            }
            break;

            case OP_WITHIN:
            {
                // (x min max -- out)
                if (stack.size() < 3)
                    return false;
                CBigNum bn1(stacktop(-3));
                CBigNum bn2(stacktop(-2));
                CBigNum bn3(stacktop(-1));
                bool fValue = (bn2 <= bn1 && bn1 < bn3);
                stack.pop_back();
                stack.pop_back();
                stack.pop_back();
                stack.push_back(fValue ? vchTrue : vchFalse);
            }
            break;


            //
            // Crypto
            //
            case OP_RIPEMD160:
            case OP_SHA1:
            case OP_SHA256:
            case OP_HASH160:
            case OP_HASH256:
            {
                // (in -- hash)
                if (stack.size() < 1)
                    return false;
                valtype& vch = stacktop(-1);
                valtype vchHash(opcode == OP_RIPEMD160 || opcode == OP_SHA1 || opcode == OP_HASH160 ? 20 : 32);
                if (opcode == OP_RIPEMD160)
                    RIPEMD160(&vch[0], vch.size(), &vchHash[0]);
                else if (opcode == OP_SHA1)
                    SHA1(&vch[0], vch.size(), &vchHash[0]);
                else if (opcode == OP_SHA256)
                    SHA256(&vch[0], vch.size(), &vchHash[0]);
                else if (opcode == OP_HASH160)
                {
                    uint160 hash160 = Hash160(vch);
                    memcpy(&vchHash[0], &hash160, sizeof(hash160));
                }
                else if (opcode == OP_HASH256)
                {
                    uint256 hash = Hash(vch.begin(), vch.end());
                    memcpy(&vchHash[0], &hash, sizeof(hash));
                }
                stack.pop_back();
                stack.push_back(vchHash);
            }
            break;

            case OP_CODESEPARATOR:
            {
                // Hash starts after the code separator
                pbegincodehash = pc;
            }
            break;

            case OP_CHECKSIG:
            case OP_CHECKSIGVERIFY:
            {
                // (sig pubkey -- bool)
                if (stack.size() < 2)
                    return false;

                valtype& vchSig    = stacktop(-2);
                valtype& vchPubKey = stacktop(-1);

                ////// debug print
                //PrintHex(vchSig.begin(), vchSig.end(), "sig: %s\n");
                //PrintHex(vchPubKey.begin(), vchPubKey.end(), "pubkey: %s\n");

                // Subset of script starting at the most recent codeseparator
                CScript scriptCode(pbegincodehash, pend);

                // Drop the signature, since there's no way for a signature to sign itself
                scriptCode.FindAndDelete(CScript(vchSig));

                bool fSuccess = CheckSig(vchSig, vchPubKey, scriptCode, txTo, nIn, nHashType);

                stack.pop_back();
                stack.pop_back();
                stack.push_back(fSuccess ? vchTrue : vchFalse);
                if (opcode == OP_CHECKSIGVERIFY)
                {
                    if (fSuccess)
                        stack.pop_back();
                    else
                        pc = pend;
                }
            }
            break;

            case OP_CHECKMULTISIG:
            case OP_CHECKMULTISIGVERIFY:
            {
                // ([sig ...] num_of_signatures [pubkey ...] num_of_pubkeys -- bool)

                int i = 1;
                if (stack.size() < i)
                    return false;

                int nKeysCount = CBigNum(stacktop(-i)).getint();
                if (nKeysCount < 0)
                    return false;
                int ikey = ++i;
                i += nKeysCount;
                if (stack.size() < i)
                    return false;

                int nSigsCount = CBigNum(stacktop(-i)).getint();
                if (nSigsCount < 0 || nSigsCount > nKeysCount)
                    return false;
                int isig = ++i;
                i += nSigsCount;
                if (stack.size() < i)
                    return false;

                // Subset of script starting at the most recent codeseparator
                CScript scriptCode(pbegincodehash, pend);

                // Drop the signatures, since there's no way for a signature to sign itself
                for (int i = 0; i < nSigsCount; i++)
                {
                    valtype& vchSig = stacktop(-isig-i);
                    scriptCode.FindAndDelete(CScript(vchSig));
                }

                bool fSuccess = true;
                while (fSuccess && nSigsCount > 0)
                {
                    valtype& vchSig    = stacktop(-isig);
                    valtype& vchPubKey = stacktop(-ikey);

                    // Check signature
                    if (CheckSig(vchSig, vchPubKey, scriptCode, txTo, nIn, nHashType))
                    {
                        isig++;
                        nSigsCount--;
                    }
                    ikey++;
                    nKeysCount--;

                    // If there are more signatures left than keys left,
                    // then too many signatures have failed
                    if (nSigsCount > nKeysCount)
                        fSuccess = false;
                }

                while (i-- > 0)
                    stack.pop_back();
                stack.push_back(fSuccess ? vchTrue : vchFalse);

                if (opcode == OP_CHECKMULTISIGVERIFY)
                {
                    if (fSuccess)
                        stack.pop_back();
                    else
                        pc = pend;
                }
            }
            break;

            default:
                return false;
        }
    }


    if (pvStackRet)
        *pvStackRet = stack;
    return (stack.empty() ? false : CastToBool(stack.back()));
}

#undef top









uint256 SignatureHash(CScript scriptCode, const CTransaction& txTo, unsigned int nIn, int nHashType)
{
    if (nIn >= txTo.vin.size())
    {
        printf("ERROR: SignatureHash() : nIn=%d out of range\n", nIn);
        return 1;
    }
    CTransaction txTmp(txTo);

    // In case concatenating two scripts ends up with two codeseparators,
    // or an extra one at the end, this prevents all those possible incompatibilities.
    scriptCode.FindAndDelete(CScript(OP_CODESEPARATOR));

    // Blank out other inputs' signatures
    for (int i = 0; i < txTmp.vin.size(); i++)
        txTmp.vin[i].scriptSig = CScript();
    txTmp.vin[nIn].scriptSig = scriptCode;

    // Blank out some of the outputs
    if ((nHashType & 0x1f) == SIGHASH_NONE)
    {
        // Wildcard payee
        txTmp.vout.clear();

        // Let the others update at will
        for (int i = 0; i < txTmp.vin.size(); i++)
            if (i != nIn)
                txTmp.vin[i].nSequence = 0;
    }
    else if ((nHashType & 0x1f) == SIGHASH_SINGLE)
    {
        // Only lockin the txout payee at same index as txin
        unsigned int nOut = nIn;
        if (nOut >= txTmp.vout.size())
        {
            printf("ERROR: SignatureHash() : nOut=%d out of range\n", nOut);
            return 1;
        }
        txTmp.vout.resize(nOut+1);
        for (int i = 0; i < nOut; i++)
            txTmp.vout[i].SetNull();

        // Let the others update at will
        for (int i = 0; i < txTmp.vin.size(); i++)
            if (i != nIn)
                txTmp.vin[i].nSequence = 0;
    }

    // Blank out other inputs completely, not recommended for open transactions
    if (nHashType & SIGHASH_ANYONECANPAY)
    {
        txTmp.vin[0] = txTmp.vin[nIn];
        txTmp.vin.resize(1);
    }

    // Serialize and hash
    CDataStream ss(SER_GETHASH);
    ss.reserve(10000);
    ss << txTmp << nHashType;
    return Hash(ss.begin(), ss.end());
}


bool CheckSig(vector<unsigned char> vchSig, vector<unsigned char> vchPubKey, CScript scriptCode,
              const CTransaction& txTo, unsigned int nIn, int nHashType)
{
    CKey key;
    if (!key.SetPubKey(vchPubKey))
        return false;

    // Hash type is one byte tacked on to the end of the signature
    if (vchSig.empty())
        return false;
    if (nHashType == 0)
        nHashType = vchSig.back();
    else if (nHashType != vchSig.back())
        return false;
    vchSig.pop_back();

    if (key.Verify(SignatureHash(scriptCode, txTo, nIn, nHashType), vchSig))
        return true;

    return false;
}










//通过传入公钥脚本即锁定脚本，最终生成并返回一个解决方法向量
bool Solver(const CScript& scriptPubKey, vector<pair<opcodetype, valtype> >& vSolutionRet)
{
    // Templates提供两种模板
    static vector<CScript> vTemplates;//定义一个静态的名字为模板的脚本向量，元素为脚本类型
    if (vTemplates.empty())//如果模板是空的，则执行
    {					   //以下两种锁定脚本类型
        // Standard tx, sender provides pubkey, receiver adds signature
        vTemplates.push_back(CScript() << OP_PUBKEY << OP_CHECKSIG);//将这两个操作码添加到脚本中，生成一个新的脚本
																	//并将这个脚本添加到模版的末尾
																	//P2PK类型(pay-to-public key)
        // Short account number tx, sender provides hash of pubkey, receiver provides signature and pubkey
        vTemplates.push_back(CScript() << OP_DUP << OP_HASH160 << OP_PUBKEYHASH << OP_EQUALVERIFY << OP_CHECKSIG);
    }									    	//将这五个操作码添加到脚本中，生成新的脚本并将这个脚本添加到模板末尾
												//P2PKH类型(pay-to-public key hash)
    // Scan templates
    const CScript& script1 = scriptPubKey;     //锁定脚本
    foreach(const CScript& script2, vTemplates)//按照脚本进行遍历模板，每一项就是一个脚本类型
    {
        vSolutionRet.clear();  //清空解决方法向量
        opcodetype opcode1, opcode2;//定义两个操作码变量
        vector<unsigned char> vch1, vch2;//定义两个向量，可能用于存储返回的内容

        // Compare
        CScript::const_iterator pc1 = script1.begin();
        CScript::const_iterator pc2 = script2.begin();
        loop//for(;;)一直循环
        {
            bool f1 = script1.GetOp(pc1, opcode1, vch1);//获取脚本script1的操作码
            bool f2 = script2.GetOp(pc2, opcode2, vch2);
            if (!f1 && !f2)//f1 与 f2 都是false
            {
                // Success
                reverse(vSolutionRet.begin(), vSolutionRet.end());//栈先进后出
                return true;//循环结束并返回true
            }
            else if (f1 != f2)//script1获取操作码失败且script2获取操作码成功，或者反之
            {
                break;       //跳出loop循环
            }
            else if (opcode2 == OP_PUBKEY)//获取的操作码为OP_PUBKEY
            {
                if (vch1.size() <= sizeof(uint256))//如果提取的公钥字节大小小于32字节，跳出循环
                    break;
                vSolutionRet.push_back(make_pair(opcode2, vch1));//将提取的公钥和相应的操作码组成一个配对存到解决方法向量vSolutionRet
            }
            else if (opcode2 == OP_PUBKEYHASH)//获取的操作码为OP_PUBKEYHASH,公钥hash值
            {
                if (vch1.size() != sizeof(uint160))//如果获取的字节流小于20字节，跳出循环
                    break;
                vSolutionRet.push_back(make_pair(opcode2, vch1));//将提取的公钥hash值和相应的操作码组成一个配对存到解决方法向量vSolutionRet
            }
            else if (opcode1 != opcode2)//如果返回的操作码不相等，跳出循环
            {
                break;
            }
        }
    }

    vSolutionRet.clear();//清空解决方法向量
    return false;
}






/********************************************************************
#define CRITICAL_BLOCK(cs)     \
    for (bool fcriticalblockonce=true; fcriticalblockonce; assert(("break caught by CRITICAL_BLOCK!", !fcriticalblockonce)), fcriticalblockonce=false)  \
    for (CCriticalBlock criticalblock(cs); fcriticalblockonce && (cs.pszFile=__FILE__, cs.nLine=__LINE__, true); fcriticalblockonce=false, cs.pszFile=NULL, cs.nLine=0)

*********************************************************************/

/********************************************************************
***传入锁定脚本
***hash值
***返回一个脚本scriptSigRet
***mapKeys：公钥对应私钥
***mapPubKeys: 公钥hash值(hash160)对应公钥
*********************************************************************/
bool Solver(const CScript& scriptPubKey, uint256 hash, int nHashType, CScript& scriptSigRet)
{
    scriptSigRet.clear();//将传入的脚本对象清空

    vector<pair<opcodetype, valtype> > vSolution;//定义一个向量，元素类型为pair<opcodetype,valtype>
    if (!Solver(scriptPubKey, vSolution))  //得到修改后的vSolution,
        return false;

    // Compile solution
    CRITICAL_BLOCK(cs_mapKeys)
    {			//pair<opcodetype,valtype>& item
        foreach(PAIRTYPE(opcodetype, valtype)& item, vSolution)//#define foreach  BOOST_FOREACH [boost库]
        {				//按照向量vSolution中每一项进行遍历
            if (item.first == OP_PUBKEY)//P2PK类型
            {
                // Sign
                const valtype& vchPubKey = item.second;//取出公钥
                if (!mapKeys.count(vchPubKey))//map<vector<unsigned char>, CPrivKey> mapKeys;
                    return false;//查找键值等于公钥vchPubKey的个数，返回0，则没找到
                if (hash != 0)
                {
                    vector<unsigned char> vchSig;
                    if (!CKey::Sign(mapKeys[vchPubKey], hash, vchSig))//直接用类进行调用Sign函数进行签名操作
                        return false;							//运用公钥对应的私钥
                    vchSig.push_back((unsigned char)nHashType);//将hash类型压入
                    scriptSigRet << vchSig;//将所得的签名写到签名脚本中并返回
                }
            }
            else if (item.first == OP_PUBKEYHASH)//P2PKH类型
            {
                // Sign and give pubkey//map<uint160, vector<unsigned char> > mapPubKeys;
                map<uint160, valtype>::iterator mi = mapPubKeys.find(uint160(item.second));//按键值进行查找，
                if (mi == mapPubKeys.end())//没找到返回end()迭代器							//返回一个迭代器
                    return false;
                const vector<unsigned char>& vchPubKey = (*mi).second;//读出公钥值
                if (!mapKeys.count(vchPubKey))//按照公钥值进行查找
                    return false;
                if (hash != 0)
                {
                    vector<unsigned char> vchSig;
                    if (!CKey::Sign(mapKeys[vchPubKey], hash, vchSig))//签名运算
                        return false;
                    vchSig.push_back((unsigned char)nHashType);//hash类型压入
                    scriptSigRet << vchSig << vchPubKey;//将签名及公钥写到签名脚本中，生成解锁脚本
                }
            }
        }
    }

    return true;
}


bool IsMine(const CScript& scriptPubKey)
{
    CScript scriptSig;
    return Solver(scriptPubKey, 0, 0, scriptSig);
}


bool ExtractPubKey(const CScript& scriptPubKey, bool fMineOnly, vector<unsigned char>& vchPubKeyRet)
{
    vchPubKeyRet.clear();

    vector<pair<opcodetype, valtype> > vSolution;
    if (!Solver(scriptPubKey, vSolution))
        return false;

    CRITICAL_BLOCK(cs_mapKeys)
    {
        foreach(PAIRTYPE(opcodetype, valtype)& item, vSolution)
        {
            valtype vchPubKey;
            if (item.first == OP_PUBKEY)
            {
                vchPubKey = item.second;
            }
            else if (item.first == OP_PUBKEYHASH)
            {
                map<uint160, valtype>::iterator mi = mapPubKeys.find(uint160(item.second));
                if (mi == mapPubKeys.end())
                    continue;
                vchPubKey = (*mi).second;
            }
            if (!fMineOnly || mapKeys.count(vchPubKey))
            {
                vchPubKeyRet = vchPubKey;
                return true;
            }
        }
    }
    return false;
}


bool ExtractHash160(const CScript& scriptPubKey, uint160& hash160Ret)
{
    hash160Ret = 0;

    vector<pair<opcodetype, valtype> > vSolution;
    if (!Solver(scriptPubKey, vSolution))
        return false;

    foreach(PAIRTYPE(opcodetype, valtype)& item, vSolution)
    {
        if (item.first == OP_PUBKEYHASH)
        {
            hash160Ret = uint160(item.second);
            return true;
        }
    }
    return false;
}


bool SignSignature(const CTransaction& txFrom, CTransaction& txTo, unsigned int nIn, int nHashType, CScript scriptPrereq)
{
    assert(nIn < txTo.vin.size());
    CTxIn& txin = txTo.vin[nIn];
    assert(txin.prevout.n < txFrom.vout.size());
    const CTxOut& txout = txFrom.vout[txin.prevout.n];

    // Leave out the signature from the hash, since a signature can't sign itself.
    // The checksig op will also drop the signatures from its hash.
    uint256 hash = SignatureHash(scriptPrereq + txout.scriptPubKey, txTo, nIn, nHashType);

    if (!Solver(txout.scriptPubKey, hash, nHashType, txin.scriptSig))
        return false;

    txin.scriptSig = scriptPrereq + txin.scriptSig;

    // Test solution
    if (scriptPrereq.empty())
        if (!EvalScript(txin.scriptSig + CScript(OP_CODESEPARATOR) + txout.scriptPubKey, txTo, nIn))
            return false;

    return true;
}


bool VerifySignature(const CTransaction& txFrom, const CTransaction& txTo, unsigned int nIn, int nHashType)
{
    assert(nIn < txTo.vin.size());
    const CTxIn& txin = txTo.vin[nIn];
    if (txin.prevout.n >= txFrom.vout.size())
        return false;
    const CTxOut& txout = txFrom.vout[txin.prevout.n];//取出前一个交易的第n个交易输出（从0开始）

    if (txin.prevout.hash != txFrom.GetHash())
        return false;

    return EvalScript(txin.scriptSig + CScript(OP_CODESEPARATOR) + txout.scriptPubKey, txTo, nIn, nHashType);
}
