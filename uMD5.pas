 {------------------------------------------------------------------}
 { uMD5 Hashsum Evaluation Unit For Borland Delphi (Ver 1.0)         }

{ Version for Avl, Kol and Vcl!                                    }

 { Copyright (c) 2003 by Avenger                                    }
 { E-mail: xavenger@mail.ru                                         }
 { Web-site: http://www.nhtboard.da.ru/                             }

 { Derived from the RSA Data Security, Inc.                         }
 { MD5 Message-Digest Algorithm described in RFC 1321               }
 { http://www.faqs.org/rfcs/rfc1321.html                            }
 {------------------------------------------------------------------}

 //раскомментируйте необходимую линию
 //остальные должны быть закомментированы !!!

 //{$define Avl}
 //{$define Kol}
{$DEFINE Vcl}
{$R-}
{$Q-}

{-------------------------------------------------------------------}

unit uMD5;

interface

uses
 {$IFDEF MSWINDOWS}
 Windows,
 {$ELSE}
 {$ENDIF}
{$IFDEF avl}
 Avl
{$ENDIF}
{$IFDEF Vcl}
 SysUtils, Classes
{$ENDIF}
{$IFDEF Kol}
 Kol
{$ENDIF};

type
 { Тип TMD5Digest используется для получения
   результата функций вычисления хеш-суммы.
   Содержимое записи можно использовать
   как набор из 4 целых чисел, или как
   массив из 16 байт }
 PMD5Digest = ^TMD5Digest;
 TMD5Digest = record
  case integer of
   0: (A, B, C, D: longint);
   1: (v: array[0..15] of byte);
 end;

function MD5WithSolt(const S: string): string;

function MD5Print(const s: string): string; inline;
function MD5String(const S: string): string; overload;

// вычисление хеш-суммы для строки
function MD5StringDigest(const S: ansistring): TMD5Digest; overload;

// вычисление хеш-суммы для файла
function MD5File(const FileName: string): TMD5Digest;

// вычисление хеш-суммы для содержиого потока Stream
function MD5Stream(const Stream: {$IFDEF Kol}pStream{$ELSE}TStream{$ENDIF}): TMD5Digest;

// вычисление хеш-суммы для произвольного буфера
function MD5Buffer(const Buffer; Size: integer): TMD5Digest;

// преобразование хеш-суммы в строку из шестнадцатеричных цифр
function MD5DigestToStr(const Digest: TMD5Digest): string;

// сравнение двух хеш-сумм
function MD5DigestCompare(const Digest1, Digest2: TMD5Digest): boolean;

implementation

{
Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.

License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.

License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.
}

type
 // UINT4 = LongWord;

 PArray4UINT4 = ^TArray4UINT4;
 TArray4UINT4 = array[0..3] of longword;
 PArray2UINT4 = ^TArray2UINT4;
 TArray2UINT4 = array[0..1] of longword;
 PArray16Byte = ^TArray16Byte;
 TArray16Byte = array[0..15] of byte;
 PArray64Byte = ^TArray64Byte;
 TArray64Byte = array[0..63] of byte;

 PByteArray = ^TByteArray;
 TByteArray = array[0..0] of byte;

 PUINT4Array = ^TUINT4Array;
 TUINT4Array = array[0..0] of longword;

 PMD5Context = ^TMD5Context;

 TMD5Context = record
  state:  TArray4UINT4;
  Count:  TArray2UINT4;
  buffer: TArray64Byte;
 end;

const
 S11 = 7;
 S12 = 12;
 S13 = 17;
 S14 = 22;
 S21 = 5;
 S22 = 9;
 S23 = 14;
 S24 = 20;
 S31 = 4;
 S32 = 11;
 S33 = 16;
 S34 = 23;
 S41 = 6;
 S42 = 10;
 S43 = 15;
 S44 = 21;
 Solt = '237fhsudhfaushfo';

function _F(x, y, z: longword): longword; inline;
begin
 Result := (((x) and (y)) or ((not x) and (z)));
end;

function _G(x, y, z: longword): longword; inline;
begin
 Result := (((x) and (z)) or ((y) and (not z)));
end;

function _H(x, y, z: longword): longword; inline;
begin
 Result := ((x) xor (y) xor (z));
end;

function _I(x, y, z: longword): longword; inline;
begin
 Result := ((y) xor ((x) or (not z)));
end;

function ROTATE_LEFT(x, n: longword): longword; inline;
begin
 Result := (((x) shl (n)) or ((x) shr (32 - (n))));
end;

procedure FF(var a: longword; b, c, d, x, s, ac: longword); inline;
begin
 a := a + _F(b, c, d) + x + ac;
 a := ROTATE_LEFT(a, s);
 a := a + b;
end;

procedure GG(var a: longword; b, c, d, x, s, ac: longword); inline;
begin
 a := a + _G(b, c, d) + x + ac;
 a := ROTATE_LEFT(a, s);
 a := a + b;
end;

procedure HH(var a: longword; b, c, d, x, s, ac: longword); inline;
begin
 a := a + _H(b, c, d) + x + ac;
 a := ROTATE_LEFT(a, s);
 a := a + b;
end;

procedure II(var a: longword; b, c, d, x, s, ac: longword); inline;
begin
 a := a + _I(b, c, d) + x + ac;
 a := ROTATE_LEFT(a, s);
 a := a + b;
end;

procedure MD5Encode(Output: PByteArray; Input: PUINT4Array; Len: longword);
var
 i, j: longword;
begin
 j := 0;
 i := 0;
 while j < Len do
 begin
  Output[j] := byte(Input[i] and $FF);
  Output[j + 1] := byte((Input[i] shr 8) and $FF);
  Output[j + 2] := byte((Input[i] shr 16) and $FF);
  Output[j + 3] := byte((Input[i] shr 24) and $FF);
  Inc(j, 4);
  Inc(i);
 end;
end;

procedure MD5Decode(Output: PUINT4Array; Input: PByteArray; Len: longword);
var
 i, j: longword;
begin
 j := 0;
 i := 0;
 while j < Len do
 begin
  Output[i] := longword(Input[j]) or (longword(Input[j + 1]) shl 8) or (longword(Input[j + 2]) shl 16) or
   (longword(Input[j + 3]) shl 24);
  Inc(j, 4);
  Inc(i);
 end;
end;

procedure MD5_memcpy(Output: PByteArray; Input: PByteArray; Len: longword); inline;
begin
 Move(Input^, Output^, Len);
end;

procedure MD5_memset(Output: PByteArray; Value: integer; Len: longword); inline;
begin
 FillChar(Output^, Len, byte(Value));
end;

procedure MD5Transform(State: PArray4UINT4; Buffer: PArray64Byte);
var
 a, b, c, d: longword;
 x: array[0..15] of longword;
begin
 a := State[0];
 b := State[1];
 c := State[2];
 d := State[3];
 MD5Decode(PUINT4Array(@x), PByteArray(Buffer), 64);

 FF(a, b, c, d, x[0], S11, $D76AA478);
 FF(d, a, b, c, x[1], S12, $E8C7B756);
 FF(c, d, a, b, x[2], S13, $242070DB);
 FF(b, c, d, a, x[3], S14, $C1BDCEEE);
 FF(a, b, c, d, x[4], S11, $F57C0FAF);
 FF(d, a, b, c, x[5], S12, $4787C62A);
 FF(c, d, a, b, x[6], S13, $A8304613);
 FF(b, c, d, a, x[7], S14, $FD469501);
 FF(a, b, c, d, x[8], S11, $698098D8);
 FF(d, a, b, c, x[9], S12, $8B44F7AF);
 FF(c, d, a, b, x[10], S13, $FFFF5BB1);
 FF(b, c, d, a, x[11], S14, $895CD7BE);
 FF(a, b, c, d, x[12], S11, $6B901122);
 FF(d, a, b, c, x[13], S12, $FD987193);
 FF(c, d, a, b, x[14], S13, $A679438E);
 FF(b, c, d, a, x[15], S14, $49B40821);

 GG(a, b, c, d, x[1], S21, $F61E2562);
 GG(d, a, b, c, x[6], S22, $C040B340);
 GG(c, d, a, b, x[11], S23, $265E5A51);
 GG(b, c, d, a, x[0], S24, $E9B6C7AA);
 GG(a, b, c, d, x[5], S21, $D62F105D);
 GG(d, a, b, c, x[10], S22, $2441453);
 GG(c, d, a, b, x[15], S23, $D8A1E681);
 GG(b, c, d, a, x[4], S24, $E7D3FBC8);
 GG(a, b, c, d, x[9], S21, $21E1CDE6);
 GG(d, a, b, c, x[14], S22, $C33707D6);
 GG(c, d, a, b, x[3], S23, $F4D50D87);

 GG(b, c, d, a, x[8], S24, $455A14ED);
 GG(a, b, c, d, x[13], S21, $A9E3E905);
 GG(d, a, b, c, x[2], S22, $FCEFA3F8);
 GG(c, d, a, b, x[7], S23, $676F02D9);
 GG(b, c, d, a, x[12], S24, $8D2A4C8A);

 HH(a, b, c, d, x[5], S31, $FFFA3942);
 HH(d, a, b, c, x[8], S32, $8771F681);
 HH(c, d, a, b, x[11], S33, $6D9D6122);
 HH(b, c, d, a, x[14], S34, $FDE5380C);
 HH(a, b, c, d, x[1], S31, $A4BEEA44);
 HH(d, a, b, c, x[4], S32, $4BDECFA9);
 HH(c, d, a, b, x[7], S33, $F6BB4B60);
 HH(b, c, d, a, x[10], S34, $BEBFBC70);
 HH(a, b, c, d, x[13], S31, $289B7EC6);
 HH(d, a, b, c, x[0], S32, $EAA127FA);
 HH(c, d, a, b, x[3], S33, $D4EF3085);
 HH(b, c, d, a, x[6], S34, $4881D05);
 HH(a, b, c, d, x[9], S31, $D9D4D039);
 HH(d, a, b, c, x[12], S32, $E6DB99E5);
 HH(c, d, a, b, x[15], S33, $1FA27CF8);
 HH(b, c, d, a, x[2], S34, $C4AC5665);

 II(a, b, c, d, x[0], S41, $F4292244);
 II(d, a, b, c, x[7], S42, $432AFF97);
 II(c, d, a, b, x[14], S43, $AB9423A7);
 II(b, c, d, a, x[5], S44, $FC93A039);
 II(a, b, c, d, x[12], S41, $655B59C3);
 II(d, a, b, c, x[3], S42, $8F0CCC92);
 II(c, d, a, b, x[10], S43, $FFEFF47D);
 II(b, c, d, a, x[1], S44, $85845DD1);
 II(a, b, c, d, x[8], S41, $6FA87E4F);
 II(d, a, b, c, x[15], S42, $FE2CE6E0);
 II(c, d, a, b, x[6], S43, $A3014314);
 II(b, c, d, a, x[13], S44, $4E0811A1);
 II(a, b, c, d, x[4], S41, $F7537E82);
 II(d, a, b, c, x[11], S42, $BD3AF235);
 II(c, d, a, b, x[2], S43, $2AD7D2BB);
 II(b, c, d, a, x[9], S44, $EB86D391);

 Inc(State[0], a);
 Inc(State[1], b);
 Inc(State[2], c);
 Inc(State[3], d);

 MD5_memset(PByteArray(@x), 0, SizeOf(x));
end;

procedure MD5Init(var Context: TMD5Context);
begin
 Context := Default(TMD5Context);
 Context.state[0] := $67452301;
 Context.state[1] := $EFCDAB89;
 Context.state[2] := $98BADCFE;
 Context.state[3] := $10325476;
end;

procedure MD5Update(var Context: TMD5Context; Input: PByteArray; InputLen: longword);
var
 i, StrIndex, PartLen: longword;

begin
 StrIndex := longword((Context.Count[0] shr 3) and $3F);
 Inc(Context.Count[0], longword(InputLen) shl 3);
 if Context.Count[0] < longword(InputLen) shl 3 then
  Inc(Context.Count[1]);
 Inc(Context.Count[1], longword(InputLen) shr 29);
 PartLen := 64 - StrIndex;
 if InputLen >= PartLen then
 begin
  MD5_memcpy(PByteArray(@Context.buffer[StrIndex]), Input, PartLen);
  MD5Transform(@Context.state, @Context.buffer);
  i := PartLen;
  while i + 63 < InputLen do
  begin
   MD5Transform(@Context.state, PArray64Byte(@Input[i]));
   Inc(i, 64);
  end;
  StrIndex := 0;
 end
 else
  i := 0;
 MD5_memcpy(PByteArray(@Context.buffer[StrIndex]), PByteArray(@Input[i]), InputLen - i);
end;

procedure MD5Final(const Digest: TMD5Digest; var Context: TMD5Context);
const
 Padding: TArray64Byte = (
  $80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0);
var
 Bits: array[0..7] of byte;
 StrIndex, PadLen: longword;
begin
 MD5Encode(PByteArray(@Bits), PUINT4Array(@Context.Count), 8);
 StrIndex := longword((Context.Count[0] shr 3) and $3F);
 if StrIndex < 56 then
  PadLen := 56 - StrIndex
 else
  PadLen := 120 - StrIndex;
 MD5Update(Context, PByteArray(@Padding), PadLen);
 MD5Update(Context, PByteArray(@Bits), 8);
 MD5Encode(PByteArray(@Digest), PUINT4Array(@Context.state), 16);
 MD5_memset(PByteArray(@Context), 0, SizeOf(Context));
end;

function MD5DigestToStr(const Digest: TMD5Digest): string;
var
 i: integer;
begin
 Result := '';
 for i := 0 to 15 do
  Result := Result +
{$IFDEF Kol}Int2Hex{$ELSE}
   IntToHex
{$ENDIF}
   (Digest.v[i], 2);
end;

function MD5WithSolt(const S: string): string;
begin
 Result := MD5DigestToStr(MD5StringDigest(ansistring(s + Solt)));
end;

function MD5Print(const s: string): string;
begin
 Result := s;
end;

function MD5String(const S: string): string;
begin
 Result := MD5DigestToStr(MD5StringDigest(ansistring(s)));
end;

function MD5StringDigest(const S: ansistring): TMD5Digest; inline;
begin
 Result := MD5Buffer(PAnsiChar(S)^, Length(S));
end;

function MD5File(const FileName: string): TMD5Digest;
var
{$IFDEF Avl}
 F: TFileStream;
{$ENDIF}
{$IFDEF Vcl}
 F: TFileStream;
{$ENDIF}
{$IFDEF Kol}
 F: pStream;
{$ENDIF}
begin
{$IFDEF Kol}
 F := NewReadFileStream(FileName);
{$ELSE}
 F := TFileStream.Create(FileName, fmOpenRead);
{$ENDIF}
 try
  Result := MD5Stream(F);
 finally
  FreeAndNil(F);
 end;
end;

function MD5Stream(const Stream: {$IFDEF Kol}pStream{$ELSE}TStream{$ENDIF}): TMD5Digest;
var
 Buffer: Pointer;
 Size: integer;
 SavePos: integer;
 //Handle: THandle;
begin
 Size := Stream.Size;
 SavePos := Stream.Position;
 try
  Stream.Seek(0,
{$IFDEF Kol}spBegin{$ELSE}
   soFromBeginning
{$ENDIF}
   );

  GetMem(Buffer, Size);
  //if Handle = 0 then
  // Exit; //OutOfMemoryError;
  //Buffer := LocalLock(Handle);
  if Buffer = nil then
  begin
   //LocalFree(Handle);
   Exit;
   //   OutOfMemoryError;
  end;
  try
   Stream.Read(Buffer^, Size);
   Result := MD5Buffer(Buffer^, Size);
  finally
   FreeMem(Buffer);
   //LocalUnlock(Handle);
   //LocalFree(Handle);
  end;
 finally
  Stream.Seek(SavePos,
{$IFDEF Kol}spBegin{$ELSE}
   soFromBeginning
{$ENDIF}
   );
 end;
end;

function MD5Buffer(const Buffer; Size: integer): TMD5Digest;
var
 Context: TMD5Context;
begin
 MD5Init(Context);
 MD5Update(Context, PByteArray(@Buffer), Size);
 MD5Final(Result, Context);
end;

function MD5DigestCompare(const Digest1, Digest2: TMD5Digest): boolean;
begin
 Result := False;
 if Digest1.A <> Digest2.A then
  Exit;
 if Digest1.B <> Digest2.B then
  Exit;
 if Digest1.C <> Digest2.C then
  Exit;
 if Digest1.D <> Digest2.D then
  Exit;
 Result := True;
end;

end.
