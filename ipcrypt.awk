#!/usr/bin/awk -f
# ipcrypt compact AWK: variant=det|nd|ndx mode=enc|dec key=HEX [ip=IP] [tweak=HEX] [data=HEX]
BEGIN{pa();if(variant==""||mode=="")F("need variant & mode");it();
 if(variant=="det"){if(l(keyhex)!=32)F("det key 32 hex");h2b(keyhex,KEY,16);ek(KEY,RK);
  if(mode=="enc"){if(ip=="")F("ip");i2b(ip,PT);ae(PT,CT,RK);print b2i(CT)"\n";exit}
  else if(mode=="dec"){if(ip=="")F("ip enc");i2b(ip,CT);ad(CT,PT,RK);print b2i(PT)"\n";exit}
  else F("bad mode")}
 else if(variant=="nd"){if(l(keyhex)!=32)F("nd key 32 hex");h2b(keyhex,KEY,16);ek(KEY,RK);
  if(mode=="enc"){if(ip=="")F("ip");if(tweakhex!=""){if(l(tweakhex)!=16)F("tweak 16");h2b(tweakhex,T8,8)}else prb(T8,8);ptw(T8,T16);i2b(ip,PT);ke(PT,T16,CT,RK);b2h(T8,8);b2h(CT,16);print"\n";exit}
  else if(mode=="dec"){if(datahex==""||l(datahex)!=48)F("data 48");sb(substr(datahex,1,16),T8,8);sb(substr(datahex,17),CT,16);ptw(T8,T16);kd(CT,T16,PT,RK);print b2i(PT)"\n";exit}
  else F("bad mode")}
 else if(variant=="ndx"){if(l(keyhex)!=64)F("ndx key 64");h2b(substr(keyhex,1,32),K1,16);h2b(substr(keyhex,33),K2,16);ek(K1,RK);ek(K2,RK2);
  if(mode=="enc"){if(ip=="")F("ip");if(tweakhex!=""){if(l(tweakhex)!=32)F("tweak 32");h2b(tweakhex,T16,16)}else prb(T16,16);i2b(ip,PT);ae(T16,ET,RK2);for(i=0;i<16;i++)TMP[i]=bxor(PT[i],ET[i]);ae(TMP,ENC,RK);for(i=0;i<16;i++)CT[i]=bxor(ENC[i],ET[i]);b2h(T16,16);b2h(CT,16);print"\n";exit}
  else if(mode=="dec"){if(datahex==""||l(datahex)!=64)F("data 64");sb(substr(datahex,1,32),T16,16);sb(substr(datahex,33),CT,16);ae(T16,ET,RK2);for(i=0;i<16;i++)TMP[i]=bxor(CT[i],ET[i]);ad(TMP,DEC,RK);for(i=0;i<16;i++)PT[i]=bxor(DEC[i],ET[i]);print b2i(PT)"\n";exit}
  else F("bad mode")}
 else F("unknown variant")}
function pa(i,k){for(i=1;i<ARGC;i++)if(ARGV[i]~/=/){split(ARGV[i],k,/=/);A[k[1]]=k[2];ARGV[i]=""}mode=A["mode"];variant=A["variant"];ip=A["ip"];keyhex=A["key"];tweakhex=A["tweak"];datahex=A["data"]}
function F(m){print"Error: "m>"/dev/stderr";exit 1}
function it(i,x){if(INIT)return;INIT=1;split("63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0 b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15 04 c7 23 c3 18 96 05 9a 07 12 80 e2 eb 27 b2 75 09 83 2c 1a 1b 6e 5a a0 52 3b d6 b3 29 e3 2f 84 53 d1 00 ed 20 fc b1 5b 6a cb be 39 4a 4c 58 cf d0 ef aa fb 43 4d 33 85 45 f9 02 7f 50 3c 9f a8 51 a3 40 8f 92 9d 38 f5 bc b6 da 21 10 ff f3 d2 cd 0c 13 ec 5f 97 44 17 c4 a7 7e 3d 64 5d 19 73 60 81 4f dc 22 2a 90 88 46 ee b8 14 de 5e 0b db e0 32 3a 0a 49 06 24 5c c2 d3 ac 62 91 95 e4 79 e7 c8 37 6d 8d d5 4e a9 6c 56 f4 ea 65 7a ae 08 ba 78 25 2e 1c a6 b4 c6 e8 dd 74 1f 4b bd 8b 8a 70 3e b5 66 48 03 f6 0e 61 35 57 b9 86 c1 1d 9e e1 f8 98 11 69 d9 8e 94 9b 1e 87 e9 ce 55 28 df 8c a1 89 0d bf e6 42 68 41 99 2d 0f b0 54 bb 16",ST," ");split("52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb 7c e3 39 82 9b 2f ff 87 34 8e 43 44 c4 de e9 cb 54 7b 94 32 a6 c2 23 3d ee 4c 95 0b 42 fa c3 4e 08 2e a1 66 28 d9 24 b2 76 5b a2 49 6d 8b d1 25 72 f8 f6 64 86 68 98 16 d4 a4 5c cc 5d 65 b6 92 6c 70 48 50 fd ed b9 da 5e 15 46 57 a7 8d 9d 84 90 d8 ab 00 8c bc d3 0a f7 e4 58 05 b8 b3 45 06 d0 2c 1e 8f ca 3f 0f 02 c1 af bd 03 01 13 8a 6b 3a 91 11 41 4f 67 dc ea 97 f2 cf ce f0 b4 e6 73 96 ac 74 22 e7 ad 35 85 e2 f9 37 e8 1c 75 df 6e 47 f1 1a 71 1d 29 c5 89 6f b7 62 0e aa 18 be 1b fc 56 3e 4b c6 d2 79 20 9a db c0 fe 78 cd 5a f4 1f dd a8 33 88 07 c7 31 b1 12 10 59 27 80 ec 5f 60 51 7f a9 19 b5 4a 0d 2d e5 7a 9f 93 c9 9c ef a0 e0 3b 4d ae 2a f5 b0 c8 eb bb 3c 83 53 99 61 17 2b 04 7e ba 77 d6 26 e1 69 14 63 55 21 0c 7d",IT," ");split("01 02 04 08 10 20 40 80 1b 36",RC," ");for(i=0;i<256;i++){SBOX[i]=hv(ST[i+1]);INV_SBOX[i]=hv(IT[i+1])}for(i=0;i<10;i++)RCON[i]=hv(RC[i+1]);p2[0]=1;for(i=1;i<8;i++)p2[i]=p2[i-1]*2;for(x=0;x<256;x++){m2=ml2(x);M2[x]=m2;M3[x]=bx(m2,x)}}
function bx(a,b,i,r,ab,bb){r=0;for(i=0;i<8;i++){ab=int(a/p2[i])%2;bb=int(b/p2[i])%2;if(ab!=bb)r+=p2[i]}return r}
function ml2(x,s){s=(x*2)%256;if(x>=128)s=bx(s,27);return s%256}
function hv(h,i,c,d,v){v=0;for(i=1;i<=length(h);i++){c=substr(h,i,1);if(c>="A"&&c<="F")c=tolower(c);if(c~/[0-9]/)d=c+0;else if(c=="a")d=10;else if(c=="b")d=11;else if(c=="c")d=12;else if(c=="d")d=13;else if(c=="e")d=14;else if(c=="f")d=15;else F("hex"c);v=v*16+d}return v}
function h2b(hex,a,e,i,b){if(l(hex)%2)F("hex even");if(e!=""&&l(hex)!=e*2)F("len"e);n=l(hex)/2;for(i=0;i<n;i++){b=substr(hex,2*i+1,2);a[i]=hv(b)}}
function sb(seg,a,n,i){if(l(seg)!=n*2)F("seg");for(i=0;i<n;i++)a[i]=hv(substr(seg,2*i+1,2))}
function b2h(a,n,i){for(i=0;i<n;i++)printf "%02x",a[i]%256}
function prb(o,n,i){srand();for(i=0;i<n;i++)o[i]=int(rand()*256)}
function i2b(ip,o){if(ip~/\./)p4(ip,o);else p6(ip,o)}
function p4(ip,o,p,c,i,v){c=split(ip,p,/\./);if(c!=4)F("ipv4");for(i=0;i<10;i++)o[i]=0;o[10]=255;o[11]=255;for(i=0;i<4;i++){v=p[i+1]+0;if(v<0||v>255)F("octet");o[12+i]=v}}
function p6(ip,o,i,L,R,pl,pr,l,r,m,hs,k,val,v){if(ip=="::"){for(i=0;i<16;i++)o[i]=0;return}if(ip~/::/){split(ip,LR,/::/);L=LR[1];R=LR[2];l=L!=""?split(L,pl,/:/):0;r=R!=""?split(R,pr,/:/):0;m=8-(l+r);if(m<1)F("::");k=0;for(i=1;i<=l;i++)hs[++k]=pl[i];for(i=0;i<m;i++)hs[++k]="0";for(i=1;i<=r;i++)hs[++k]=pr[i]}else{k=split(ip,hs,/:/);if(k!=8)F("ipv6")}if(k!=8)F("exp");for(i=0;i<8;i++){val=hs[i+1];if(val=="")val="0";if(val!~/^[0-9A-Fa-f]{1,4}$/)F("hex");v=hv(val);o[2*i]=int(v/256);o[2*i+1]=v%256}}
function b2i(b,i,v,hs,ls,ll,cs,cl,res,is4){is4=1;for(i=0;i<10;i++)if(b[i]!=0){is4=0;break}if(is4&&b[10]==255&&b[11]==255)return b[12]"."b[13]"."b[14]"."b[15];for(i=0;i<8;i++){v=b[2*i]*256+b[2*i+1];hs[i]=v}ls=-1;ll=0;cs=-1;cl=0;for(i=0;i<8;i++){if(hs[i]==0){if(cs==-1){cs=i;cl=1}else cl++}else{if(cl>ll&&cl>=2){ls=cs;ll=cl}cs=-1;cl=0}}if(cl>ll&&cl>=2){ls=cs;ll=cl}res="";for(i=0;i<8;i++){if(ll>=2&&i==ls){res=(res==""?"::":res"::");i+=(ll-1);continue}if(res!=""&&substr(res,length(res))!=":")res=res":";res=res sprintf("%x",hs[i])}return(res==""?"::":res)}
function sbt(s,i){for(i=0;i<16;i++)s[i]=SBOX[s[i]]}function isbt(s,i){for(i=0;i<16;i++)s[i]=INV_SBOX[s[i]]}
function shr(s,t){t[0]=s[0];t[1]=s[5];t[2]=s[10];t[3]=s[15];t[4]=s[4];t[5]=s[9];t[6]=s[14];t[7]=s[3];t[8]=s[8];t[9]=s[13];t[10]=s[2];t[11]=s[7];t[12]=s[12];t[13]=s[1];t[14]=s[6];t[15]=s[11];cp(t,s)}
function ishr(s,t){t[0]=s[0];t[1]=s[13];t[2]=s[10];t[3]=s[7];t[4]=s[4];t[5]=s[1];t[6]=s[14];t[7]=s[11];t[8]=s[8];t[9]=s[5];t[10]=s[2];t[11]=s[15];t[12]=s[12];t[13]=s[9];t[14]=s[6];t[15]=s[3];cp(t,s)}
function mc(s,o,i,s0,s1,s2,s3){for(i=0;i<4;i++){s0=s[4*i];s1=s[4*i+1];s2=s[4*i+2];s3=s[4*i+3];o[4*i]=bx(bx(M2[s0],M3[s1]),bx(s2,s3));o[4*i+1]=bx(bx(s0,M2[s1]),bx(M3[s2],s3));o[4*i+2]=bx(bx(s0,s1),bx(M2[s2],M3[s3]));o[4*i+3]=bx(bx(M3[s0],s1),bx(s2,M2[s3]))}cp(o,s)}
function m09(b){return bx(M2[M2[M2[b]]],b)}function m0B(b){return bx(bx(M2[M2[M2[b]]],M2[b]),b)}
function m0D(b,x2,x4,x8){x2=M2[b];x4=M2[x2];x8=M2[x4];return bx(bx(x8,x4),b)}function m0E(b,x2,x4,x8){x2=M2[b];x4=M2[x2];x8=M2[x4];return bx(bx(x8,x4),x2)}
function imc(s,o,i,c0,c1,c2,c3){for(i=0;i<4;i++){c0=s[4*i];c1=s[4*i+1];c2=s[4*i+2];c3=s[4*i+3];o[4*i]=bx(bx(m0E(c0),m0B(c1)),bx(m0D(c2),m09(c3)));o[4*i+1]=bx(bx(m09(c0),m0E(c1)),bx(m0B(c2),m0D(c3)));o[4*i+2]=bx(bx(m0D(c0),m09(c1)),bx(m0E(c2),m0B(c3)));o[4*i+3]=bx(bx(m0B(c0),m0D(c1)),bx(m09(c2),m0E(c3)))}cp(o,s)}
function cp(src,dst,i){for(i=0;i<16;i++)dst[i]=src[i]}
function ek(k,R,r,t0,t1,t2,t3,j,t,b,pb){for(j=0;j<16;j++)R[0,j]=k[j];for(r=0;r<10;r++){t0=R[r,12];t1=R[r,13];t2=R[r,14];t3=R[r,15];t=t0;t0=t1;t1=t2;t2=t3;t3=t; t0=SBOX[t0];t1=SBOX[t1];t2=SBOX[t2];t3=SBOX[t3];t0=bx(t0,RCON[r]);for(j=0;j<4;j++){if(j==0){R[r+1,0]=bx(R[r,0],t0);R[r+1,1]=bx(R[r,1],t1);R[r+1,2]=bx(R[r,2],t2);R[r+1,3]=bx(R[r,3],t3)}else{b=4*j;pb=4*(j-1);R[r+1,b]=bx(R[r,b],R[r+1,pb]);R[r+1,b+1]=bx(R[r,b+1],R[r+1,pb+1]);R[r+1,b+2]=bx(R[r,b+2],R[r+1,pb+2]);R[r+1,b+3]=bx(R[r,b+3],R[r+1,pb+3])}}}}
function ae(pt,ct,R,s,i,j){for(i=0;i<16;i++)s[i]=bx(pt[i],R[0,i]);for(i=1;i<=9;i++){sbt(s);shr(s);mc(s);for(j=0;j<16;j++)s[j]=bx(s[j],R[i,j])}sbt(s);shr(s);for(i=0;i<16;i++)ct[i]=bx(s[i],R[10,i])}
function ad(ct,pt,R,s,i,r,j){for(i=0;i<16;i++)s[i]=bx(ct[i],R[10,i]);ishr(s);isbt(s);for(r=9;r>0;r--){for(i=0;i<16;i++)s[i]=bx(s[i],R[r,i]);imc(s);ishr(s);isbt(s)}for(i=0;i<16;i++)pt[i]=bx(s[i],R[0,i])}
function ptw(t8,t16,i){for(i=0;i<4;i++){t16[4*i]=t8[2*i];t16[4*i+1]=t8[2*i+1];t16[4*i+2]=0;t16[4*i+3]=0}}
function ke(pt,tw,ct,R,st,j,i){for(i=0;i<16;i++)st[i]=bx(bx(pt[i],R[0,i]),tw[i]);for(i=0;i<9;i++){sbt(st);shr(st);mc(st);for(j=0;j<16;j++)st[j]=bx(bx(st[j],R[i+1,j]),tw[j])}sbt(st);shr(st);for(i=0;i<16;i++)ct[i]=bx(bx(st[i],R[10,i]),tw[i])}
function kd(ct,tw,pt,R,st,i,r){for(i=0;i<16;i++)st[i]=bx(bx(ct[i],R[10,i]),tw[i]);ishr(st);isbt(st);for(r=9;r>0;r--){for(i=0;i<16;i++)st[i]=bx(bx(st[i],R[r,i]),tw[i]);imc(st);ishr(st);isbt(st)}for(i=0;i<16;i++)pt[i]=bx(bx(st[i],R[0,i]),tw[i])}
function l(s){return length(s)}

