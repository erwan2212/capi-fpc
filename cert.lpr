program certfpc;

uses windows,sysutils,registry,classes,
  wcrypt2,schannel,
  rcmdline in '..\rcmdline-master\rcmdline.pas',
  cryptutils,
  ddetours;

{$ifdef CPU64}
const POINTER_MASK =$E35A172CD96214A0;
{$endif}
{$ifdef CPU32}
const POINTER_MASK =$E35A172C;
{$endif}

type


UInt32_t = UInt32;

_KEY =record
    pUnknown:pvoid;
    dwUnknow:dword;
    dwFlags:dword;
end;
_pkey=^_key;
_ppkey=^_pkey;

key_data_s=record
 unknown:pvoid;  //xor'ed
 alg:uint32_t;
 flags:uint32_t;
 key_size:uint32_t;
 key_bytes:pvoid;
end;
 pkey_data_s=^key_data_s;

 magic_s=record
 key_data:pkey_data_s;
end;
 pmagic_s=^magic_s;

HCRYPTKEY_=record

 CPGenKey:pointer;       //4
 CPDeriveKey:pointer;    //8
 CPDestroyKey:pointer;   //12
 CPSetKeyParam:pointer;  //16
 CPGetKeyParam:pointer;  //20
 CPExportKey:pointer;    //24
 CPImportKey:pointer;    //28
 CPEncrypt:pointer;      //32
 CPDecrypt:pointer;      //36
 CPDuplicateKey:pointer; //40
 hCryptProv_:HCRYPTPROV;  //44
 magic:pmagic_s; //is XOR-ed with a constant value, 0xE35A172C.
end;
PHCRYPTKEY_=^HCRYPTKEY_;


  //
var
  cmd: TCommandLineReader;
  blobRaw:pointer=nil;
  blob:pointer=nil;
  buffer:array[0..4095] of byte;
  bufferlen,blobRawlen,bloblen,providertype,written,mode:dword;
  hfile_:thandle=thandle(-1);
  input_handle:thandle;
  pem,output,data,cn:string;

  nCPExportKey:function(
    hProv:HCRYPTPROV;hKey:HCRYPTKEY;hExpKey:HCRYPTKEY;dwBlobType:DWORD;
    dwFlags:DWORD;pbData:PBYTE;pdwDataLen:PDWORD):boolean; stdcall=nil;


  {
  Const SIMPLEBLOB                = 1
  Const PUBLICKEYBLOB             = 6
  Const PRIVATEKEYBLOB            = 7
  Const PLAINTEXTKEYBLOB          = 8
  }
  //see https://github.com/iSECPartners/jailbreak
  function MyCPExportKey(
    hProv:HCRYPTPROV;hKey:HCRYPTKEY;hExpKey:HCRYPTKEY;dwBlobType:DWORD;
    dwFlags:DWORD;pbData:PBYTE;pdwDataLen:PDWORD):boolean; stdcall;
  var
    magic:nativeuint;
    key_data_s:nativeuint;
    p:pointer=nil;
    d:dword=1234;
    ppKey:_ppkey = nil;
    dwFlags_:dword=0;
  begin
    //p:=@d;
    //will display the address of the iptrValue variable,
    //then the address stored in that variable,
    //and then the value stored at that address
    //0148F9A4 -> 0148F9A0 -> 1234
    //writeln(Format('%p -> %p -> %d', [@p, p, dword(p^)]));
    //writeln(inttohex(nativeuint(pointer(p)),8)); //address stored in p aka 0148F9A0
    //writeln(inttohex(nativeuint(pointer(@p)),8)); //address of p aka 0148F9A4
    //writeln('MyCPExportKey');
    //writeln('dwBlobType:'+inttostr(dwBlobType));
    //
    ppKey := _ppkey(hKey xor POINTER_MASK );
    dwFlags_:= ppkey^.dwFlags ;
    //writeln('dwFlags_:'+inttostr(dwFlags_));
    ppkey^.dwFlags:=$4001;
    //*(DWORD*)(*(DWORD*)(*(DWORD*)(hKey +0x2C) ^ 0xE35A172C) + 8)
    //writeln('pointer(hkey):'+inttohex(nativeuint(pointer(@hkey)),8));
    result:=nCPExportKey(hProv,hKey,hExpKey,dwBlobType,dwFlags,pbData,pdwDataLen);
    ppkey^.dwFlags:=dwflags;
  end;

//certutil -v blob.bin
function SaveBlob(RootKey: HKEY; const Key: string):boolean;
const
  marker:array [0..7] of byte=($20,00,00,00,01,00,00,00);
var
  Registry: TRegistry;
  Bytes: TBytes;
  hFile:thandle=thandle(-1);
  size:dword=0;
  pos:dword=0;
  i:word;
begin
  result:=false;
  writeln(key);
  Registry := TRegistry.Create;
  Try
    Registry.RootKey := RootKey;
    if Registry.OpenKeyReadOnly(Key)=true then
       begin
       SetLength(Bytes, Registry.GetDataSize('blob'));
       writeln(length(bytes));
       size:= registry.ReadBinaryData('blob',bytes[0],length(bytes)); //Pointer(Bytes)^
       if size>0 then
          begin
          writeln(size);
          for i:=0 to size -1 do
            begin
              if comparemem(@bytes[i],@marker[0],sizeof(marker))= true then pos:=i+sizeof(marker)+4;
            end;
          writeln(pos);
          //https://blog.nviso.eu/2019/08/28/extracting-certificates-from-the-windows-registry/
          //locate 20 00 00 00 01 00 00 00 xx xx xx xx and truncate to start with 30 xx
          hFile := CreateFile(PChar('blob.cer'), GENERIC_READ or GENERIC_WRITE, FILE_SHARE_READ or FILE_SHARE_WRITE, nil, CREATE_ALWAYS , FILE_ATTRIBUTE_NORMAL, 0);
          if hfile<>thandle(-1) then
             begin
             if WriteFile(hfile, bytes[pos], length(bytes)-pos, size, nil) then result:=true;
             CloseHandle(hfile);
             end;
          end;
       end;
  Finally
    Registry.Free;
  End;
end;

procedure EnumSubKeys(RootKey: HKEY; const Key: string);
var
  Registry: TRegistry;
  SubKeyNames: TStringList;
  Name: string;
begin
  writeln(key);
  Registry := TRegistry.Create;
  Try
    Registry.RootKey := RootKey;
    Registry.OpenKeyReadOnly(Key);
    SubKeyNames := TStringList.Create;
    Try
      Registry.GetKeyNames(SubKeyNames);
      for Name in SubKeyNames do
        Writeln(Name);
    Finally
      SubKeyNames.Free;
    End;
  Finally
    Registry.Free;
  End;
end;

begin

    if paramcount=0 then
       begin
       writeln('try cert --help');
       exit;
       end;

    cmd := TCommandLineReader.create;
    cmd.declareflag ('export','export to a pfx file, use store and fitler on subject or sha1');
    cmd.declareFlag ('force','will hook cpexportkey to export non exportable pvk');
    cmd.declareflag ('dumpcert','dump from registry to a cer file, use store and sha1');
    cmd.declareflag ('import','import a cert from filename to store');
    cmd.declareflag ('mkcert','make a cert, read from store/subject for issuer, and cn');
    cmd.declareflag ('enumcerts','enumerate certificates in a store');
    cmd.declareflag ('enumstores','enumerate stores');
    cmd.declareflag ('delete','use store and filter on subject or sha1');
    cmd.declareflag ('pvk2pem','encode/convert a pvk to pem');
    cmd.declareflag ('rsa2pvk','export a decrypted rsa blob/raw capi key to pvk');
    cmd.declareflag ('rsa2pem','convert a decrypted rsa blob to a base64 pem');
    cmd.declareflag ('der2pem','convert a binary cert to base64 pem');
    cmd.declareflag ('pem2der','convert a base64 pem to der');
    cmd.declareflag ('bin2base64','convert data to base64');
    cmd.declareflag ('bin2hex','convert data to hexadecimal');
    cmd.declareflag ('hash','hash data');

    cmd.declareString('store', 'certificate store','MY');
    cmd.declareString('subject', 'subject used when exporting or deleting or making');
    cmd.declareString('cn', 'used by mkcert','CN=localhost');
    cmd.declareString('sha1', 'sha1 used when exporting or deleting');
    cmd.declarestring('profile', 'user or machine','user' );
    cmd.declarestring('password', 'cert password' );
    cmd.declarestring('filename', 'cert filename' );
    cmd.declarestring('data', 'anything you want' );
    cmd.declarestring('algo', 'SHA512 SHA284 SHA256 SHA1 MD5 MD4 MD2' );

    cmd.parse(cmdline);

    //
    input_handle := GetStdHandle(STD_INPUT_HANDLE);
      if GetFileType(input_handle) <> FILE_TYPE_CHAR then
         begin
         ZeroMemory(@buffer[0],sizeof(buffer));
         data:='';
         while Readfile(input_handle,buffer[0],sizeof(buffer),bufferlen ,nil) =true do
            begin
            if bufferlen=0 then exit;
            data:=data+strpas(pchar(@buffer[0]));
            ZeroMemory(@buffer[0],sizeof(buffer));
            end;
         //sLineBreak
         if pos(#13#10,data)=length(data)-1 then delete(data,pos(#13#10,data),2) ;
         //writeln(data);
         end;
    //

    if cmd.readstring('profile')='machine' then CERT_SYSTEM_STORE:=CERT_SYSTEM_STORE_LOCAL_MACHINE;
 //
 if cmd.existsProperty('enumstores') then
 begin
   //EnumSubKeys(HKEY_CURRENT_USER ,'software\microsoft\systemcertificates');
   if enumstore =true then writeln('ok') else writeln('nok');
 end;

 if cmd.existsProperty('dumpcert') then
 begin
    if saveblob(HKEY_CURRENT_USER ,'software\microsoft\systemcertificates\'+cmd.readstring('store')+'\certificates\'+cmd.readstring('sha1'))=true
       then writeln('ok') else writeln('not ok');
 end;

 if (cmd.existsProperty('export')) and (cmd.existsProperty('subject'))
    then
    begin
    if cmd.existsProperty('force') then
       begin
       LoadLibrary ('rsaenh.dll'); //or else intercept may/will fail
       @nCPExportKey    :=ddetours.InterceptCreate(GetProcAddress(GetModuleHandle('rsaenh.dll'), 'CPExportKey') , @myCPExportKey);
       end;
       if ExportCert(widestring(cmd.readstring('store')),cmd.readstring('subject'),'')=true
         then writeln('ok') else writeln('nok');
    end;

  if (cmd.existsProperty('export')) and (cmd.existsProperty('sha1'))
    then
    begin
       if cmd.existsProperty('force') then
          begin
          LoadLibrary ('rsaenh.dll'); //or else intercept may/will fail
          @nCPExportKey    :=ddetours.InterceptCreate(GetProcAddress(GetModuleHandle('rsaenh.dll'), 'CPExportKey') , @myCPExportKey);
          end;
       if ExportCert(widestring(cmd.readstring('store')),'',cmd.readstring('sha1'))=true
         then writeln('ok') else writeln('nok');
    end;

  if cmd.existsProperty('enumcerts')
     then EnumCertificates(cmd.readstring('store'));

  if (cmd.existsProperty('delete')) and (cmd.existsProperty('subject'))
     then if DeleteCertificate(widestring(cmd.readstring('store')),cmd.readstring('subject'))=true
          then writeln('ok') else writeln('nok');

   if (cmd.existsProperty('delete')) and (cmd.existsProperty('sha1'))
     then if DeleteCertificate(widestring(cmd.readstring('store')),'',cmd.readstring('sha1'))=true
          then writeln('ok') else writeln('nok');

   if cmd.existsProperty('import')
      then if ImportCert(widestring(cmd.readstring('store')),cmd.readstring('filename'),widestring(cmd.readstring('password')))=true
           then writeln('ok') else writeln('nok');



     if cmd.existsProperty('mkcert') then
       begin
       cn:=cmd.readstring('cn');
       DoCreateCertificate (cmd.readstring('store'),cmd.readstring('subject'),cn); //'CN=Toto8,E=toto@example.com'
       end;

     if cmd.existsProperty('pem2der') then
        begin
        hfile_ := CreateFile(pchar(cmd.readstring('filename')), GENERIC_READ , FILE_SHARE_READ or FILE_SHARE_WRITE, nil, OPEN_EXISTING , FILE_ATTRIBUTE_NORMAL, 0);
        if hfile_=thandle(-1) then begin writeln('invalid handle',1);exit;end;
        ReadFile (hfile_,buffer[0],sizeof(buffer),bufferlen,nil);
        closehandle(hfile_);
        if bufferlen <=0 then exit;
        //
        if pem_to_der (@buffer[0],bufferlen,blob,bloblen) then
          begin
          hfile_ := CreateFile(PChar(ChangeFileExt (cmd.readstring('filename'),'.der')), GENERIC_READ or GENERIC_WRITE, FILE_SHARE_READ or FILE_SHARE_WRITE, nil, CREATE_ALWAYS , FILE_ATTRIBUTE_NORMAL, 0);
          if WriteFile(hfile_, blob^, bloblen, bufferlen, nil)=true
             then writeln('done') else writeln('failed');
          CloseHandle(hfile_);
          end;
        //
        end;

     if cmd.existsProperty('der2pem') then
        begin
        hfile_ := CreateFile(pchar(cmd.readstring('filename')), GENERIC_READ , FILE_SHARE_READ or FILE_SHARE_WRITE, nil, OPEN_EXISTING , FILE_ATTRIBUTE_NORMAL, 0);
        if hfile_=thandle(-1) then begin writeln('invalid handle',1);exit;end;
        ReadFile (hfile_,buffer[0],sizeof(buffer),bufferlen,nil);
        closehandle(hfile_);
        if bufferlen <=0 then exit;
        //
        if der_to_pem (@buffer[0],bufferlen,pem) then
          begin
          hfile_ := CreateFile(PChar(ChangeFileExt (cmd.readstring('filename'),'.crt')), GENERIC_READ or GENERIC_WRITE, FILE_SHARE_READ or FILE_SHARE_WRITE, nil, CREATE_ALWAYS , FILE_ATTRIBUTE_NORMAL, 0);
          if WriteFile(hfile_, pem[1], length(pem), bufferlen, nil)=true
             then writeln('done') else writeln('failed');
          CloseHandle(hfile_);
          end;
        //
        end;

     if cmd.existsProperty('rsa2pvk') then
        begin
        hfile_ := CreateFile(pchar(cmd.readstring('filename')), GENERIC_READ , FILE_SHARE_READ or FILE_SHARE_WRITE, nil, OPEN_EXISTING , FILE_ATTRIBUTE_NORMAL, 0);
        if hfile_=thandle(-1) then begin writeln('invalid handle',1);exit;end;
        ReadFile (hfile_,buffer[0],sizeof(buffer),bufferlen,nil);
        closehandle(hfile_);
        if bufferlen>0 then
          if kull_m_key_capi_decryptedkey_to_raw(nil,0,@buffer[0],bufferlen,CALG_RSA_KEYX,blobRaw,blobRawlen,providertype)=true then
          if raw_to_pvk (blobRaw,blobRawlen,AT_KEYEXCHANGE,blob,bloblen) then
           begin
             hfile_ := CreateFile(pchar('decoded.pvk'), GENERIC_READ or GENERIC_WRITE , FILE_SHARE_READ or FILE_SHARE_WRITE, nil, CREATE_ALWAYS , FILE_ATTRIBUTE_NORMAL, 0);
             if hfile_=thandle(-1) then begin writeln('invalid handle',1);exit;end;
             if writefile(hfile_,blob^,bloblen,bloblen,nil)=false then writeln('writefile nok');
             closehandle(hfile_);
             writeln('done');
             end;
        end;

     if cmd.existsProperty('pvk2pem') then
        begin
             hfile_ := CreateFile(pchar(cmd.readstring('filename')), GENERIC_READ , FILE_SHARE_READ or FILE_SHARE_WRITE, nil, OPEN_EXISTING , FILE_ATTRIBUTE_NORMAL, 0);
             if hfile_=thandle(-1) then begin writeln('invalid handle',1);exit;end;
             ReadFile (hfile_,buffer[0],sizeof(buffer),bufferlen,nil);
             closehandle(hfile_);
             //writeln(bufferlen);
             //
             if pvk_to_pem (@buffer[0]+sizeof(PVK_FILE_HDR ),pem) then
               begin
               hfile_ := CreateFile(pchar('decoded.pem'), GENERIC_READ or GENERIC_WRITE , FILE_SHARE_READ or FILE_SHARE_WRITE, nil, CREATE_ALWAYS , FILE_ATTRIBUTE_NORMAL, 0);
               if hfile_=thandle(-1) then begin writeln('invalid handle',1);exit;end;
               if writefile(hfile_,pem[1],length(pem),written,nil)=false then writeln('writefile nok');
               closehandle(hfile_);
               end;
            writeln('done');
        end;

     if cmd.existsProperty('rsa2pem') then
             begin
             hfile_ := CreateFile(pchar(cmd.readstring('filename')), GENERIC_READ , FILE_SHARE_READ or FILE_SHARE_WRITE, nil, OPEN_EXISTING , FILE_ATTRIBUTE_NORMAL, 0);
             if hfile_=thandle(-1) then begin writeln('invalid handle',1);exit;end;
             ReadFile (hfile_,buffer[0],sizeof(buffer),bufferlen,nil);
             closehandle(hfile_);
             if bufferlen>0 then
               if kull_m_key_capi_decryptedkey_to_raw(nil,0,@buffer[0],bufferlen,CALG_RSA_KEYX,blobRaw,blobRawlen,providertype)=true then
               if raw_to_pvk (blobRaw,blobRawlen,AT_KEYEXCHANGE,blob,bloblen) then
                begin
                   if pvk_to_pem (blob+sizeof(PVK_FILE_HDR ),pem) then
                     begin
                     hfile_ := CreateFile(pchar('decoded.pem'), GENERIC_READ or GENERIC_WRITE , FILE_SHARE_READ or FILE_SHARE_WRITE, nil, CREATE_ALWAYS , FILE_ATTRIBUTE_NORMAL, 0);
                     if hfile_=thandle(-1) then begin writeln('invalid handle',1);exit;end;
                     if writefile(hfile_,pem[1],length(pem),written,nil)=false then writeln('writefile nok');
                     closehandle(hfile_);
                     end;
                  writeln('done');
                  end;
             end;

     if cmd.existsProperty ('bin2base64') then
        begin
        if data='' then data:=cmd.readString ('data');
        if bin_to_base64 (@data[1],length(data),output) then writeln(stringreplace(output,' ','',[rfReplaceAll]));
        end;

     if cmd.existsProperty ('bin2hex') then
        begin
        if data='' then data:=cmd.readString ('data');
        if bin_to_hex (@data[1],length(data),output) then writeln(stringreplace(output,' ','',[rfReplaceAll]));
        end;

     if cmd.existsProperty('hash') then
     begin
     mode:=0;
     //writeln(cmd.readstring('algo'));
     if cmd.readstring('algo')='SHA512' then mode:=$0000800e;
     if cmd.readstring('algo')='SHA256' then mode:=$0000800c;
     if cmd.readstring('algo')='SHA384' then mode:=$0000800d;
     if cmd.readstring('algo')='SHA1' then mode:=$00008004;
     if cmd.readstring('algo')='MD5' then mode:=$00008003;
     if cmd.readstring('algo')='MD4' then mode:=$00008002;
     if cmd.readstring('algo')='MD2' then mode:=$00008001;
     //if mode=0 then mode:=$00008003;
     blob:=allocmem(crypto_hash_len(mode));
     if data='' then data:=cmd.readString ('data');
     if crypto_hash(mode,pointer(data),length(data),blob,crypto_hash_len(mode)) then
        begin
        if bin_to_hex (blob,crypto_hash_len(mode),output) then writeln(stringreplace(output,' ','',[rfReplaceAll]));
        end
        else writeln('failed');
     end;
end.

//check
//https://github.com/openssl/openssl/blob/master/apps/rsa.c
//https://gist.github.com/crazybyte/4142937/2b1a8e2d72af55105df0a42c9fb02b7cedd2a3a4

//convert PVK to PEM
//openssl rsa -inform PVK -in decoded.pvk -out decoded.key

//convert DER to PEM
//openssl x509 -in C:\Certificates\AnyCert.cer -text -noout
//if Expecting: TRUSTED CERTIFICATE ... -> DER
//openssl x509 -inform DER -in blob.cer -out blob.crt

//openssl x509 -modulus -noout -in blob.crt | openssl md5
//(stdin)= 7497e3aa41dad2df6cf68a935f0ee519

//openssl rsa -modulus -noout -in decoded.pem | openssl md5
//(stdin)= e9f7c743b737ca062ed2fa6aacd1dd16

//mimikatz # dpapi::capi /in:"C:\Users\erwan\AppData\Roaming\Microsoft\Crypto\RSA\S-1-5-21-2427513087-2265021005-1965656450-1001\d673096e4c9c08d6fc03c64c44117795_e65f292c-6dbf-47f8-b70f-c52e116acc05" /unprotect


