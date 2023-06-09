unit CryptUtils;

{$mode delphi}

interface

uses windows,sysutils,wcrypt2,schannel;

//
const
CERT_KEY_PROV_HANDLE_PROP_ID        = 1;
CERT_KEY_PROV_INFO_PROP_ID          = 2;
CERT_SHA1_HASH_PROP_ID              = 3;
CERT_MD5_HASH_PROP_ID               = 4;
CERT_HASH_PROP_ID                   = CERT_SHA1_HASH_PROP_ID;
CERT_KEY_CONTEXT_PROP_ID            = 5;
CERT_KEY_SPEC_PROP_ID               = 6;
CERT_IE30_RESERVED_PROP_ID          = 7;
CERT_PUBKEY_HASH_RESERVED_PROP_ID   = 8;
CERT_ENHKEY_USAGE_PROP_ID           = 9;
CERT_CTL_USAGE_PROP_ID              = CERT_ENHKEY_USAGE_PROP_ID;
CERT_NEXT_UPDATE_LOCATION_PROP_ID   = 10;
CERT_FRIENDLY_NAME_PROP_ID          = 11;
CERT_PVK_FILE_PROP_ID               = 12;
// Note, 32 - 34 are reserved for the CERT, CRL and CTL file element IDs.
CERT_FIRST_RESERVED_PROP_ID         = 13;
CERT_SIGNATURE_HASH_PROP_ID=15;
CERT_KEY_IDENTIFIER_PROP_ID = 20;
CERT_ISSUER_PUBLIC_KEY_MD5_HASH_PROP_ID     = 24;
CERT_SUBJECT_PUBLIC_KEY_MD5_HASH_PROP_ID    = 25;
const
CERT_NAME_SIMPLE_DISPLAY_TYPE=4;
CERT_NAME_ISSUER_FLAG=$1;
const
SHA1_HASH_STRING_LENGTH=40;

const
REPORT_NO_PRIVATE_KEY                 = $0001;
REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY = $0002;
EXPORT_PRIVATE_KEYS                   = $0004;
PKCS12_INCLUDE_EXTENDED_PROPERTIES    = $0010;

CRYPT_STRING_BASE64HEADER= $00000000;
CRYPT_STRING_BASE64= $00000001;
CRYPT_STRING_HEX=$00000004; //Hexadecimal only format.
CRYPT_STRING_HEXASCII=$00000005; //Hexadecimal format with ASCII character display.
CRYPT_STRING_ANY                          = $00000007;
CRYPT_STRING_HEX_ANY                      = $00000008;
CRYPT_STRING_HEXRAW=$0000000c;
CRYPT_STRING_NOCRLF=$40000000;

PROV_RSA_AES:dword = 24;

//
type

  
_RSA_GENERICKEY_BLOB=record
	Header:BLOBHEADER;
	RsaKey:RSAPUBKEY; // works with RSA2 ;)
end;
RSA_GENERICKEY_BLOB=_RSA_GENERICKEY_BLOB;
PRSA_GENERICKEY_BLOB=^_RSA_GENERICKEY_BLOB;

_PVK_FILE_HDR =record
		dwMagic:DWORD;
		dwVersion:DWORD;
		dwKeySpec:DWORD;
		dwEncryptType:DWORD;
		cbEncryptData:DWORD;
		cbPvk:DWORD;
end;
PVK_FILE_HDR=_PVK_FILE_HDR;
PPVK_FILE_HDR=^PVK_FILE_HDR;

  NCRYPT_HANDLE = ULONG_PTR;
  NCRYPT_KEY_HANDLE = ULONG_PTR;
  PNCRYPT_KEY_HANDLE = ^NCRYPT_KEY_HANDLE;
  NCRYPT_PROV_HANDLE = ULONG_PTR;
  PNCRYPT_PROV_HANDLE=^NCRYPT_PROV_HANDLE;

  function NCryptOpenKey(hProvider: NCRYPT_PROV_HANDLE;
     phKey: PNCRYPT_KEY_HANDLE; pszKeyName: LPCWSTR;
    dwLegacyKeySpec, dwFlags: DWORD): SECURITY_STATUS; stdcall; external 'ncrypt.dll';

  function NCryptGetProperty(hObject: NCRYPT_HANDLE; pszProperty: LPCWSTR;
    pbOutput: PBYTE; cbOutput: DWORD; pcbResult: PDWORD;
    dwFlags: DWORD): SECURITY_STATUS; stdcall; external 'ncrypt.dll';

function NCryptOpenStorageProvider(phProvider: PNCRYPT_PROV_HANDLE;
  pszProviderName: LPCWSTR; dwFlags: DWORD): SECURITY_STATUS; stdcall; external 'ncrypt.dll';

//ex crypt2 unit
function CryptAcquireCertificatePrivateKey(
             pCert:wcrypt2.PCCERT_CONTEXT;
             dwFlags:DWORD;
             pvParameters:pvoid;
             var phCryptProvOrNCryptKey:thandle;
             pdwKeySpec:PDWORD;
             pfCallerFreeProvOrNCryptKey:PBOOL): BOOL; stdcall;external 'crypt32.dll';

function PFXImportCertStore(pPFX:PCRYPT_DATA_BLOB;szPassword:LPCWSTR;
                             dwFlags:DWORD):HCERTSTORE; stdcall; external 'Crypt32.dll';

function PFXExportCertStoreEx(hStore: HCERTSTORE;
                             var pPFX: CRYPT_DATA_BLOB;
                             szPassword: LPCWSTR;
                             pvPra: Pointer;
                             dwFlags: DWORD): BOOL; stdcall; external 'Crypt32.dll';

function CryptStringToBinaryA(pszString: PChar; cchString: dword; dwFlags: dword;
       pbBinary: pointer;  pcbBinary: pdword; pdwSkip: pdword;
       pdwFlags: pdword): boolean; stdcall;external 'crypt32.dll';

function CertGetCertificateChain (
         hChainEngine: HCERTCHAINENGINE;
         pCertContext: wcrypt2.PCCERT_CONTEXT;
         pTime: PFILETIME;
         hAdditionalStore: HCERTSTORE;
   const pChainPara: CERT_CHAIN_PARA;
         dwFlags: DWORD;
         pvReserved: pointer;  //LPVOID;
    var  ppChainContext: PCCERT_CHAIN_CONTEXT): bool; stdcall; external 'crypt32.dll';

function CertFreeCertificateChain (
                pChainContext: PCCERT_CHAIN_CONTEXT): bool; stdcall; external 'crypt32.dll';

function CertAddCertificateLinkToStore(hCertStore: HCERTSTORE;
  pCertContext: wcrypt2.PCCERT_CONTEXT; dwAddDisposition: DWORD;
  ppStoreContext: wcrypt2.PPCCERT_CONTEXT): BOOL; stdcall;external 'crypt32.dll';

function CryptEncodeObjectEx(dwCertEncodingType: DWORD; lpszStructType: LPCSTR;
  pvStructInfo: Pointer; dwFlags: DWORD; pEncodePara: pointer{PCRYPT_ENCODE_PARA};
  pvEncoded: Pointer; var pcbEncoded: DWORD): BOOL; stdcall; external 'crypt32.dll';

function CryptBinaryToStringA(const pBinary: PBYTE; cbBinary: DWORD;
  dwFlags: DWORD; pszString: LPSTR; var pchString: DWORD): BOOL; stdcall;external 'crypt32.dll';

//
function enumstore():boolean;
function ImportCert(store:widestring;filename:string;password:widestring=''):boolean;
function ExportCert(store:widestring;subject:string;sha1:string=''):boolean;
procedure EnumCertificates(storename:string);
function DeleteCertificate(store:widestring;subject:string;sha1:string=''):boolean;
function DoCreateCertificate( storename,caname,cn:string):integer;
//
function kull_m_key_capi_decryptedkey_to_raw(publickey:LPCVOID;publickeyLen:DWORD;decrypted:LPCVOID;decryptedLen:DWORD; keyAlg:ALG_ID; var blob:PRSA_GENERICKEY_BLOB; var blobLen:DWORD; var dwProviderType:DWORD):boolean;
function raw_to_pvk(data:pointer;size:dword;keyspec:dword;var pExport:pbyte; var szPVK:DWORD):boolean;
function pvk_to_pem(data:pointer;var pem:string):boolean;
function der_to_pem(data:pointer;size:dword;var pem:string):boolean;
function pem_to_der(pPEM:pointer;pemSize:dword;var pDer:pointer;var size:dword):boolean;
function bin_to_hex(data:pointer;size:dword;var output:string):boolean;
function bin_to_base64(data:pointer;size:dword;var output:string):boolean;
//
function crypto_hash_len( hashId:ALG_ID):dword;
function crypto_hash(algid:alg_id;data:LPCVOID;dataLen:DWORD;  hash:lpvoid;hashWanted:DWORD):boolean;

var
  CERT_SYSTEM_STORE:dword=CERT_SYSTEM_STORE_CURRENT_USER;

implementation

  procedure log(msg:string;status:dword=0);
  begin
    if status<>0 then writeln(msg);
  end;

  function EnumSysCallback(pvSystemStore: Pointer; dwFlags: DWORD; pStoreInfo: PCERT_SYSTEM_STORE_INFO;
                           pvReserved: Pointer; pvArg: Pointer): BOOL; stdcall;
  var
    s: string;
  begin
     s := WideCharToString(pvSystemStore);
     //pvSystemStore := PChar(s);
     writeln(s);

    Result := true;
  end;

function enumstore():boolean;
begin
  result:=CertEnumSystemStore(CERT_SYSTEM_STORE_CURRENT_USER, nil, nil, EnumSysCallback);
end;

  function ImportCert(store:widestring;filename:string;password:widestring=''):boolean;
const
  CRYPT_USER_KEYSET=$00001000;
  CRYPT_EXPORTABLE=$00000001;
//
  PUBLICKEYBLOB        = $6;
  PRIVATEKEYBLOB       = $7;
var
  f:thandle;
  Buffer: array[0..8191] of byte;
   Size: DWORD;
   //
   blob:CRYPT_DATA_BLOB;
   pStore:hcertstore=nil; //thandle(-1);
   myStore:hcertstore=nil;
   pCert: wcrypt2.PCCERT_CONTEXT=nil;
   bResult:BOOL;
   bFreeHandle:BOOL;
   hProv:HCRYPTPROV;
   dwKeySpec:DWORD;
   //
   hUserKey:HCRYPTKEY;
   dwBlobLen:dword;
   pKeyData:lpbyte;
begin
  result:=false;
//
  F := CreateFile(PChar(FileName), GENERIC_READ, FILE_SHARE_READ, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if F = INVALID_HANDLE_VALUE then
      RaiseLastWin32Error;
    try
      if not ReadFile(F, Buffer, SizeOf(Buffer), Size, nil) then
        RaiseLastWin32Error;
    finally
      CloseHandle(F);
    end;
    //writeln('read:'+inttostr(Size));
    //
    blob.cbData :=size;
    blob.pbData :=pbyte(@buffer[0]);
    pStore:=PFXImportCertStore (@blob,pwidechar(password),CRYPT_EXPORTABLE  {or CRYPT_USER_KEYSET});
    if pStore=nil then //thandle(-1) then
      begin
        writeln('PFXImportCertStore failed');
        exit;
      end
      else writeln('PFXImportCertStore ok');
    //
    // Find the certificate in P12 file (we expect there is only one)
    pcert := CertFindCertificateInStore(pStore, X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, 0, CERT_FIND_ANY, nil, nil);
    if pcert=nil then
      begin
        writeln('CertFindCertificateInStore failed');
        exit;
      end
      else writeln('CertFindCertificateInStore ok');


    myStore := CertOpenStore(
           CERT_STORE_PROV_SYSTEM,
           0,                      // Encoding type not needed
                                   // with this PROV.
           0,                   // Accept the default HCRYPTPROV.
           CERT_SYSTEM_STORE,
                                   // Set the system store location in
                                   // the registry.
           pchar(store));                 // Could have used other predefined
                                   // system stores
                                   // including Trust, CA, or Root.
    if mystore=nil then
      begin
        writeln('CertOpenStore failed');
        exit;
      end;
    //check CertAddCertificateContextToStore or CertAddEncodedCertificateToStore ?
    if CertAddCertificateContextToStore(myStore, pcert, CERT_STORE_ADD_REPLACE_EXISTING, nil)=false then
      begin
        writeln('CertAddCertificateContextToStore failed:'+inttohex(getlasterror,8));
        //0x80092005 : The symbol CRYPT_E_EXISTS means "The object or property already exists.".
        exit;
      end;

    //
    {
     if CryptAcquireCertificatePrivateKey(wcrypt2.PCCERT_CONTEXT(pcert), 0, nil, hProv, @dwKeySpec, @bFreeHandle)=false then
      begin
        writeln('CryptAcquireCertificatePrivateKey failed');
        exit;
      end
      else writeln('CryptAcquireCertificatePrivateKey ok');
     }
    //
    //at this point we are ready to sign with CryptSignMessage or encrypt with ...
    //or use CryptExportKey
    {
    CryptGetUserKey(hProv, dwKeySpec, hUserKey) ;
    CryptExportKey(hUserKey, thandle(-1), PRIVATEKEYBLOB,  0, nil, dwBlobLen) ;
    pKeyData:=allocmem(dwBlobLen);
    CryptExportKey(hUserKey, thandle(-1), PRIVATEKEYBLOB, 0, pKeyData, dwBlobLen) ;
    }
    //

    CertFreeCertificateContext(pCert);
    if mystore<>nil then CertCloseStore(mystore, 0);
    if pStore<>nil then CertCloseStore(pStore, 0);

    result:=true;
end;

function ExportCert(store:widestring;subject:string;sha1:string=''):boolean;
const
  WidePass:widestring='';
var
  pStore, pStoreTmp: HCERTSTORE;
  pCert: wcrypt2.PCCERT_CONTEXT;
  PFX,
  Hash: CRYPT_INTEGER_BLOB;

  ChainPara: CERT_CHAIN_PARA;
  EnhkeyUsage: CERT_ENHKEY_USAGE;
  CertUsage: CERT_USAGE_MATCH;
  pChainContext: PCCERT_CHAIN_CONTEXT;
  ppCertSimpleChain: ^PCERT_SIMPLE_CHAIN;
  ppCertChainElement: ^PCERT_CHAIN_ELEMENT;

  i, j: Integer;
  Buffer: array of char; //RawByteString;
  str:string;
  junk:dword=0;
  dest:thandle;
  dwHashDataLength:dword=0;
begin
  writeln('store:'+store);
  writeln('subject:'+subject);
  writeln('hash:'+sha1);
  result:=false;
  pStore := nil; //thandle(-1);
  pStoreTmp := nil; //thandle(-1);
  pCert := nil;

  PFX.pbData := nil;
  PFX.cbData := 0;

  // Open system certificate store
  //pStore := CertOpenSystemStoreW(0, pwidechar(store));

  pStore := CertOpenStore(
       CERT_STORE_PROV_SYSTEM,
       0,                      // Encoding type not needed
                               // with this PROV.
       0,                   // Accept the default HCRYPTPROV.
       CERT_SYSTEM_STORE,
                               // Set the system store location in
                               // the registry.
       pchar(store));                 // Could have used other predefined
                               // system stores
                               // including Trust, CA, or Root.

 if pstore=nil then //thandle(-1) then
   begin
    writeln('CertOpenStore failed:'+inttostr(getlasterror));
    exit;
   end;

  // Open in-mem temporal certificate store
  pStoreTmp := CertOpenStore(LPCSTR(CERT_STORE_PROV_MEMORY), 0, 0, 0, nil);

  // HEX SHA1 Hash of the certificate to find
  if sha1<>'' then
    begin
      sha1:=stringreplace(sha1,' ','',[rfReplaceAll, rfIgnoreCase]);
      if CryptStringToBinaryA(pchar(sha1), SHA1_HASH_STRING_LENGTH,  CRYPT_STRING_HEXRAW,    nil, @dwHashDataLength, nil,nil) then
         begin
           setlength(buffer,dwHashDataLength);
           if CryptStringToBinaryA(pchar(sha1),SHA1_HASH_STRING_LENGTH,CRYPT_STRING_HEXRAW,@buffer[0],@dwHashDataLength,nil, nil) then
              begin
              Hash.cbData := Length(Buffer);
              Hash.pbData := pbyte(@Buffer[0]);
              end;
         end;

      pCert := CertFindCertificateInStore(pStore,
                                      X509_ASN_ENCODING or PKCS_7_ASN_ENCODING,
                                      0,
                                      CERT_FIND_SHA1_HASH,
                                      @Hash,
                                      nil);
    end; //if sha1<>'' then

    if subject<>'' then
    begin
    setlength(buffer,length(subject));
    str:=subject; //'mycomputer';
    copymemory(@buffer[0],@str[1],length(str));
    pCert := CertFindCertificateInStore(pStore,
                                      X509_ASN_ENCODING or PKCS_7_ASN_ENCODING,
                                      0,
                                      CERT_FIND_SUBJECT_STR_A ,//CERT_FIND_SUBJECT_STR CERT_FIND_SUBJECT_NAME
                                      @Buffer[0],
                                      nil);
    end; //if subject<>'' then

    if pcert=nil then
     begin
       writeln('CertFindCertificateInStore failed:'+inttohex(getlasterror,8));
       exit;
     end;
    //Error 0x80092004 stands for "CRYPT_E_NOT_FOUND

  // Now let's get the certificate's chain context
  EnhkeyUsage.cUsageIdentifier := 0;
  EnhkeyUsage.rgpszUsageIdentifier := nil;
  CertUsage.dwType := USAGE_MATCH_TYPE_AND;
  CertUsage.Usage := EnhkeyUsage;
  ChainPara.cbSize := SizeOf(CERT_CHAIN_PARA);
  ChainPara.RequestedUsage := CertUsage;

  if CertGetCertificateChain(0, wcrypt2.PCCERT_CONTEXT(pCert), nil, 0,
                          ChainPara, 0, nil, pChainContext)=false then
                          begin
                            writeln('CertGetCertificateChain failed');
                            exit;
                          end;

  // Iterate the chain context and add every certificate to mem-store
  ppCertSimpleChain := Pointer(pChainContext^.rgpChain);
  for i := 1 to pChainContext^.cChain do
  begin
    ppCertChainElement := pointer(ppCertSimpleChain^.rgpElement);
    for j := 1 to ppCertSimpleChain^.cElement do
    begin
      if CertAddCertificateLinkToStore(pStoreTmp,
                                    wcrypt2.PCCERT_CONTEXT(ppCertChainElement^.pCertContext),
                                    CERT_STORE_ADD_REPLACE_EXISTING,
                                    nil)=false then
                                    begin
                                      writeln('CertAddCertificateLinkToStore failed');
                                      exit;
                                    end;
      Inc(ppCertChainElement);
    end;
    Inc(ppCertSimpleChain);
  end;

  // Save to PFX ...
  PFX.pbData := nil;
  PFX.cbData := 0;
  // First a call with an empty BLOB to get the space needed
  if PFXExportCertStoreEx(pStoreTmp,
                       PFX,
                       PWideChar(WidePass),
                       nil,
                       EXPORT_PRIVATE_KEYS +
                       //REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY +
                       //REPORT_NO_PRIVATE_KEY +
                       PKCS12_INCLUDE_EXTENDED_PROPERTIES)=false then
                       begin
                         //0x8009000B (NTE_BAD_KEY_STATE)
                         writeln('1.PFXExportCertStoreEx failed:'+inttohex(getlasterror,8));
                         exit;
                       end;

  // OK, reserve the needed memory
  GetMem(PFX.pbData, PFX.cbData);

  // Fill data
  if PFXExportCertStoreEx(pStoreTmp,
                       PFX,
                       PWideChar(WidePass),
                       nil,
                       EXPORT_PRIVATE_KEYS +
                       REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY + //comment if you still want to export cert without pvk
                       //REPORT_NO_PRIVATE_KEY +
                       PKCS12_INCLUDE_EXTENDED_PROPERTIES)=false then
                       begin
                         writeln('2.PFXExportCertStoreEx failed:'+inttohex(getlasterror,8));
                         exit;
                       end;

  // Now PFX.pbData points to PFX information of length PFX.cbData
  // Write it to a temporary file that replaces your PEM files.
 if subject='' then subject:=sha1;
 Dest:=CreateFileA(PChar(subject+'.pfx'), GENERIC_WRITE, 0, nil, CREATE_ALWAYS, 0, 0);
 //writeln(PFX.cbData);
 WriteFile(Dest, PFX.pbData^, PFX.cbData, junk, nil);
 if junk=0 then writeln('WriteFile failed');
 CloseHandle(dest);

  // Free memory used
  // I deliberately did not check whether
  // previous API calls returned an error.
  // You should check.
  // Take a look to Microsoft's documentation for functions results
  // and GetLastError function for error code
  CertFreeCertificateChain(pChainContext);
  CertFreeCertificateContext(pCert);
  CertCloseStore(pStoreTmp, 0);
  CertCloseStore(pStore, 0);
  FreeMem(PFX.pbData);
  result:=true;
end;

  procedure EnumCertificates(storename:string);
 var
   hStore: HCERTSTORE=nil; //thandle(-1);
   CertContext: wcrypt2.PCCERT_CONTEXT;
   CertPropId: DWORD;
   Data: array[0..511] of Char;
   DataLen: DWORD;
   i: Integer;
   p:pwidechar;
   hProvider:NCRYPT_PROV_HANDLE =0;
   hkey:NCRYPT_KEY_HANDLE =0;
   cbResult:dword=0;
   pbOutput:array of widechar;
 begin
   try

     //hStore := CertOpenSystemStorew(0, pwidechar(widestring(StoreName)));


  hStore := CertOpenStore(
       CERT_STORE_PROV_SYSTEM_A,
       0,                      // Encoding type not needed
                               // with this PROV.
       0,                   // Accept the default HCRYPTPROV.
       CERT_SYSTEM_STORE,
                               // Set the system store location in
                               // the registry.
       pchar(storename));                 // Could have used other predefined
                               // system stores
                               // including Trust, CA, or Root.


     if hStore = nil then //thandle(-1) then
       RaiseLastWin32Error;
     try
       CertContext := CertEnumCertificatesInStore(hStore, nil);
       while CertContext <> nil do
       begin
         writeln('*********************************************');
         fillchar(data,sizeof(data),0);
         if CertGetNameString(CertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil,data, 512) <> 0
            then Writeln('SUBJECT_CERT_NAME: ', data);
         fillchar(data,sizeof(data),0);
         if CertGetNameString(CertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, nil,data, 512) <> 0
            then Writeln('ISSUER_CERT_NAME: ', data);
         //p:=getmem(CertContext.pCertInfo.Subject.cbData);
         //copymemory(p,CertContext.pCertInfo.Subject.pbData,CertContext.pCertInfo.Subject.cbData );
         //writeln(strpas(p));
         //DisplayCertContext(CertContext);
         CertPropId := CertEnumCertificateContextProperties(CertContext, 0);
         while CertPropId <> 0 do
         begin
           DataLen := 512;
           //Writeln(Format('CertPropId: %d', [CertPropId]));
           case CertPropId of
           CERT_KEY_PROV_HANDLE_PROP_ID:
           begin
             CertGetCertificateContextProperty(CertContext, CertPropId,
               @Data[0], @DataLen);
             Writeln(Format('KEY_PROV_HANDLE: $%.8x', [PDWORD(@Data[0])^]));
           end;

           CERT_KEY_PROV_INFO_PROP_ID:
           begin
             CertGetCertificateContextProperty(CertContext, CertPropId,
               @Data[0], @DataLen);
             with PCRYPT_KEY_PROV_INFO(@Data[0])^ do
             begin
               Writeln(Format('KEY_PROV_INFO = %s', [pwszContainerName]));
               //Writeln(Format('pwszProvName = %s', [pwszProvName]));
               //Writeln(Format('dwFlags = %d', [dwFlags]));
               //Writeln(Format('cProvParams = %d', [cProvParam]));
               //Writeln(Format('rgProvParam', [rgProvParam]));
               //Writeln(Format('dwKeySpec = %d', [dwKeySpec]));
               //see JwaNCrypt.pas
               try
               NCryptOpenStorageProvider(@hProvider,pwszProvName,0);
               NCryptOpenKey(hProvider ,@hkey,pwszContainerName,0,0);
               NCryptGetProperty(hKey,lpcwstr('Unique Name'),nil,0,@cbResult,0);
               setlength(pboutput,cbresult);
               NCryptGetProperty(hKey,lpcwstr('Unique Name'),@pbOutput[0],cbresult,@cbResult,0);
               writeln('Unique Name: '+strpas(pwidechar(pboutput)));
               finally
               end;
               {
               $phProvider = [IntPtr]::Zero
               [PKI.Tools]::NCryptOpenStorageProvider([ref]$phProvider,$keyProv.pwszProvName,0)
               $phKey = [IntPtr]::Zero
               [PKI.Tools]::NCryptOpenKey($phProvider,[ref]$phKey,$keyProv.pwszContainerName,0,0)
               $pcbResult = 0
               # calculate the size of the unique container name
               [PKI.Tools]::NCryptGetProperty($phKey,"Unique Name",$null,0,[ref]$pcbResult,0)
               # allocate the buffer to store unique container name.
               $pbOutput = New-Object byte[] -ArgumentList $pcbResult
               # copy unique container name to a buffer.
               [PKI.Tools]::NCryptGetProperty($phKey,"Unique Name",$pbOutput,$pbOutput.length,[ref]$pcbResult,0)
               }
             end;
             //Writeln(Format('KEY_PROV_INFO: %d', [@Data[0]])); //[EConvertError]
           end;

           CERT_FRIENDLY_NAME_PROP_ID:
           begin
             CertGetCertificateContextProperty(CertContext, CertPropId,
               @Data[0], @DataLen);
             Writeln(Format('FRIENDLY_NAME: %s', [PwideChar(@Data[0])]));
           end;
           CERT_SUBJECT_PUBLIC_KEY_MD5_HASH_PROP_ID:
           begin
             CertGetCertificateContextProperty(CertContext, CertPropId,
               @Data[0], @DataLen);
             Write('SUBJECT_PUBLIC_KEY_MD5_HASH: ');
             for i := 1 to DataLen do
               Write(Format('%.2x', [PBYTE(@Data[i - 1])^]));
             Writeln;
           end;
           CERT_ISSUER_PUBLIC_KEY_MD5_HASH_PROP_ID:
           begin
             CertGetCertificateContextProperty(CertContext, CertPropId,
               @Data[0], @DataLen);
             Write('ISSUER_PUBLIC_KEY_MD5_HASH: ');
             for i := 1 to DataLen do
               Write(Format('%.2x', [PBYTE(@Data[i - 1])^]));
             Writeln;
           end;
           CERT_SIGNATURE_HASH_PROP_ID:
           begin
             CertGetCertificateContextProperty(CertContext, CertPropId,
               @Data[0], @DataLen);
             Write('SIGNATURE_HASH: ');
             for i := 1 to DataLen do
               Write(Format('%.2x', [PBYTE(@Data[i - 1])^]));
             Writeln;
           end;
           CERT_KEY_IDENTIFIER_PROP_ID:
           begin
             CertGetCertificateContextProperty(CertContext, CertPropId,
               @Data[0], @DataLen);
             Write('KEY_IDENTIFIER: ');
             for i := 1 to DataLen do
               Write(Format('%.2x', [PBYTE(@Data[i - 1])^]));
             Writeln;
           end;
           CERT_SHA1_HASH_PROP_ID:
           begin
             CertGetCertificateContextProperty(CertContext, CertPropId,
               @Data[0], @DataLen);
             Write('SHA1_HASH: ');
             for i := 1 to DataLen do
               Write(Format('%.2x', [PBYTE(@Data[i - 1])^]));
             Writeln;
           end;
           CERT_MD5_HASH_PROP_ID:
           begin
             CertGetCertificateContextProperty(CertContext, CertPropId,
               @Data[0], @DataLen);
             Write('MD5_HASH: ');
             for i := 1 to DataLen do
               Write(Format('%.2x', [PBYTE(@Data[i - 1])^]));
             Writeln;
           end;
           else
           end;
           CertPropId := CertEnumCertificateContextProperties(CertContext,
             CertPropId);
         end;
         CertContext := CertEnumCertificatesInStore(hStore, CertContext);
       end;
 //      if GetLastError <> CRYPT_E_NOT_FOUND then
 //        RaiseLastWin32Error;
     finally
       CertCloseStore(hStore, 0);
     end;
   except
     on E: Exception do
     begin
       ExitCode := 1;
       Writeln(Format('[%s] %s', [E.ClassName, E.Message]));
     end;
   end;

 end;

  function DeleteCertificate(store:widestring;subject:string;sha1:string=''):boolean;
var
  pStore: HCERTSTORE=nil; //thandle(-1);
  dwHashDataLength:dword=0;
  Buffer: array of char;
  pCert: wcrypt2.PCCERT_CONTEXT;
  Hash: CRYPT_INTEGER_BLOB;
  str:string;
begin

 // Open system certificate store
  pStore:=nil; //thandle(-1);
  //pStore := CertOpenSystemStoreW(0, pwidechar(store));

  pStore := CertOpenStore(
       CERT_STORE_PROV_SYSTEM,
       0,                      // Encoding type not needed
                               // with this PROV.
       0,                   // Accept the default HCRYPTPROV.
       CERT_SYSTEM_STORE,
                               // Set the system store location in
                               // the registry.
       pchar(store));                 // Could have used other predefined
                               // system stores
                               // including Trust, CA, or Root.

 if pstore=nil then //thandle(-1) then
   begin
    writeln('CertOpenStore failed:'+inttostr(getlasterror));
    exit;
   end;

 // HEX SHA1 Hash of the certificate to find
  if sha1<>'' then
    begin
      sha1:=stringreplace(sha1,' ','',[rfReplaceAll, rfIgnoreCase]);
      //sha1 := '001AA5081EDA97805B4D6A9B6730CDBEE39761C3';
      if CryptStringToBinaryA(pchar(sha1), SHA1_HASH_STRING_LENGTH,  CRYPT_STRING_HEXRAW,    nil, @dwHashDataLength, nil,nil) then
         begin
           setlength(buffer,dwHashDataLength);
           if CryptStringToBinaryA(pchar(sha1),SHA1_HASH_STRING_LENGTH,CRYPT_STRING_HEXRAW,@buffer[0],@dwHashDataLength,nil, nil) then
              begin
              Hash.cbData := Length(Buffer);
              Hash.pbData := pbyte(@Buffer[0]);
              end;
         end;

  pCert := CertFindCertificateInStore(pStore,
                                      X509_ASN_ENCODING or PKCS_7_ASN_ENCODING,
                                      0,
                                      CERT_FIND_SHA1_HASH,
                                      @Hash,
                                      nil);

  end;

    if subject<>'' then
    begin
    setlength(buffer,255);
    str:=subject; //'mycomputer';
    copymemory(@buffer[0],@str[1],length(str));
    pCert := CertFindCertificateInStore(pStore,
                                      X509_ASN_ENCODING or PKCS_7_ASN_ENCODING,
                                      0,
                                      CERT_FIND_SUBJECT_STR_A ,//CERT_FIND_SUBJECT_STR CERT_FIND_SUBJECT_NAME
                                      @Buffer[0],
                                      nil);
    end;

    if pcert=nil then
     begin
       writeln('CertFindCertificateInStore failed:'+inttostr(getlasterror));
       exit;
     end;

  result:=CertDeleteCertificateFromStore(pcert);
  //
  CertFreeCertificateContext(pCert);
  CertCloseStore(pStore, 0);
end;

// Check if the given certificate has the Certificate Sign key usage
  function IsCACert( pContext : wcrypt2.PCCERT_CONTEXT):Boolean;
  const
    CERT_KEY_CERT_SIGN_KEY_USAGE        = $04;
  var
    bStatus   : Boolean;
    bKeyUsage : BYTE;
    cbSize    : DWORD;
  begin
     bStatus := FALSE;
     cbSize := 0;
     if CertGetIntendedKeyUsage(X509_ASN_ENCODING or PKCS_7_ASN_ENCODING,
                                 wcrypt2.PCERT_INFO(pContext.pCertInfo),
                                 @bKeyUsage,
                                 1) then
     begin
        if (bKeyUsage and CERT_KEY_CERT_SIGN_KEY_USAGE=CERT_KEY_CERT_SIGN_KEY_USAGE)
            and
            (CertGetCertificateContextProperty(wcrypt2.PCCERT_CONTEXT(pContext), CERT_KEY_PROV_INFO_PROP_ID,nil,@cbSize)=true) then
        begin
           bStatus := TRUE;
        end;
     end;
     Result := bStatus;
  end;

  function EncodeAndSignCertificate( pCaContext : wcrypt2.PCCERT_CONTEXT; hCaProv : HCRYPTPROV; dwKeySpec : DWORD; szDN : LPCTSTR):Boolean;
  var
    //bStatus        : Boolean;
    certInfo       : wcrypt2.CERT_INFO;
    pbEncodedName  : LPBYTE=nil;
    pbEncodedCert  : LPBYTE=nil;
    pbEncodedUsage : LPBYTE=nil;
    cbEncodedName  : DWORD=0;
    cbEncodedPubKey: DWORD=0;
    cbEncodedCert  : dword=0;
    cbEncodedUsage : dword= 0;
    hUserProv      : HCRYPTPROV=thandle(-1);
    hUserKey       : HCRYPTKEY=thandle(-1);
    pbSerial       : array[0..0] of BYTE= (1);
    sysTime        : SYSTEMTIME;
    notBefore,
    notAfter       : FILETIME;
    pPubKeyInfo    : PCERT_PUBLIC_KEY_INFO=nil;
    signAlgo       : CRYPT_ALGORITHM_IDENTIFIER;
    pszOID         : array[0..2] of LPSTR; //szOID_PKIX_KP_CLIENT_AUTH, szOID_PKIX_KP_EMAIL_PROTECTION;
    enhKeyUsage    : wcrypt2.CERT_ENHKEY_USAGE; //2, pszOID;
    pExtensions    : array[0..0] of wcrypt2.CERT_EXTENSION; //= (szOID_ENHANCED_KEY_USAGE, TRUE, (0, NULL));
    dwError        : DWORD;
    dwWrittenBytes : DWORD;
    hFile          : HANDLE;
    //
    szExport:dword=0;
    pExport:pbyte=nil;
    label end_;
  begin
     result := FALSE;

     pszOID[0]:=szOID_PKIX_KP_CLIENT_AUTH;
     pszOID[1]:=szOID_PKIX_KP_EMAIL_PROTECTION;
     //pszOID[2]:=szOID_PKIX_KP_SERVER_AUTH;

     enhKeyUsage.cUsageIdentifier :=2;
     enhKeyUsage.rgpszUsageIdentifier :=@pszOID ;

     pExtensions[0].pszObjId:=szOID_ENHANCED_KEY_USAGE;
     pExtensions[0].fCritical :=true;
     pExtensions[0].Value.cbData :=0;
     pExtensions[0].Value.pbData  :=nil;

     ZeroMemory(@signAlgo, sizeof(signAlgo));
     ZeroMemory(@certInfo, sizeof(certInfo));
     GetSystemTime(@sysTime);
     SystemTimeToFileTime(@sysTime, @notBefore);
     sysTime.wYear  := sysTime.wYear + 1;
     SystemTimeToFileTime(@sysTime, @notAfter);

     //https://learn.microsoft.com/en-us/windows/win32/seccrypto/example-c-program-using-cryptacquirecontext
     if  not CryptAcquireContextA(@hUserProv,
                              {szDN}nil,
                              MS_ENHANCED_PROV,
                              PROV_RSA_FULL,
                              {CRYPT_NEWKEYSET}{CRYPT_MACHINE_KEYSET}0) then
     begin
        dwError := GetLastError();
        if NTE_EXISTS <> dwError then begin
          writeln('Faile to create a new container. Error :' +inttostr(dwError));
        end;
        if  not CryptAcquireContextA(@hUserProv,
                                 {szDN}nil,
                                 MS_ENHANCED_PROV,
                                 PROV_RSA_FULL,
                                 0) then
        begin
           writeln('Faile to acquire a context on the user container. Error :' + inttostr(GetLastError));
        end;
     end;
     if  not CryptGetUserKey(hUserProv, AT_KEYEXCHANGE, hUserKey) then
     begin
        if  not CryptGenKey(hUserProv, AT_KEYEXCHANGE, CRYPT_ARCHIVABLE or CRYPT_EXPORTABLE , hUserKey) then
        begin
           writeln('CryptGenKey failed with error :'+ inttostr(GetLastError));
        end;
     end;
     if CertStrToNameA (X509_ASN_ENCODING,
                       szDN,
                       CERT_X500_NAME_STR,
                       nil,
                       nil,
                       @cbEncodedName,
                       nil) then
     begin
        pbEncodedName := allocmem(cbEncodedName);
        if  not CertStrToNameA (X509_ASN_ENCODING,
                          szDN,
                          CERT_X500_NAME_STR,
                          nil,
                          pbEncodedName,
                          @cbEncodedName,
                          nil) then
        begin
           writeln('CertStrToName failed with error :'+ inttostr(GetLastError));
           exit;
        end;
     end
     else
     begin
        writeln('CertStrToName failed with error :'+inttostr(GetLastError));
        exit;
     end;
     if CryptExportPublicKeyInfoEx(hUserProv,
             AT_KEYEXCHANGE,
             X509_ASN_ENCODING or PKCS_7_ASN_ENCODING,
             szOID_RSA_RSA,
             0,
             nil,
             nil,
             @cbEncodedPubKey) then
     begin
        pPubKeyInfo := allocmem(cbEncodedPubKey);
        if  not CryptExportPublicKeyInfoEx(hUserProv,
                AT_KEYEXCHANGE,
                X509_ASN_ENCODING or PKCS_7_ASN_ENCODING,
                szOID_RSA_RSA,
                0,
                nil,
                pPubKeyInfo,
                @cbEncodedPubKey) then
        begin
           writeln('CryptExportPublicKeyInfoEx failed with error :'+inttostr(GetLastError));
        end;
     end
     else
     begin
        writeln('CryptExportPublicKeyInfoEx failed with error :'+ inttostr(GetLastError));
     end;
     if CryptEncodeObject(X509_ASN_ENCODING or PKCS_7_ASN_ENCODING,
                           szOID_ENHANCED_KEY_USAGE,
                           @enhKeyUsage,
                           nil,
                           @cbEncodedUsage) then
     begin
        pbEncodedUsage := allocmem(cbEncodedUsage);
        if  not CryptEncodeObject(X509_ASN_ENCODING or PKCS_7_ASN_ENCODING,
                              szOID_ENHANCED_KEY_USAGE,
                              @enhKeyUsage,
                              pbEncodedUsage,
                              @cbEncodedUsage) then
        begin
           writeln('CryptEncodeObject failed with error :'+ inttostr(GetLastError));
        end;
     end
     else
     begin
        writeln('CryptEncodeObject failed with error :'+ inttostr(GetLastError));
     end;
     pExtensions[0].Value.cbData := cbEncodedUsage;
     pExtensions[0].Value.pbData := pbEncodedUsage;
     certInfo.dwVersion := CERT_V3;
     certInfo.SerialNumber.cbData := 1;
     certInfo.SerialNumber.pbData := pbSerial;
     certInfo.SignatureAlgorithm.pszObjId := szOID_RSA_SHA1RSA;
     certInfo.Issuer := pCaContext.pCertInfo.Subject;
     certInfo.NotBefore := notBefore;
     certInfo.NotAfter := notAfter;
     certInfo.Subject.cbData := cbEncodedName;
     certInfo.Subject.pbData := pbEncodedName;
     certInfo.SubjectPublicKeyInfo := pPubKeyInfo^;
     certInfo.cExtension := 1;
     certInfo.rgExtension := pExtensions;
     signAlgo.pszObjId := szOID_RSA_SHA1RSA;
     if CryptSignAndEncodeCertificate(hCaProv,
                                       dwKeySpec,
                                       X509_ASN_ENCODING,
                                       X509_CERT_TO_BE_SIGNED,
                                       @certInfo,
                                       @signAlgo,
                                       nil,
                                       nil,
                                       @cbEncodedCert) then
     begin
        pbEncodedCert := allocmem(cbEncodedCert);
        if CryptSignAndEncodeCertificate(hCaProv,
                                          dwKeySpec,
                                          X509_ASN_ENCODING,
                                          X509_CERT_TO_BE_SIGNED,
                                          @certInfo,
                                          @signAlgo,
                                          nil,
                                          pbEncodedCert,
                                          @cbEncodedCert) then
        begin
           //
           {
           if CryptExportKey(hUserKey,0, PRIVATEKEYBLOB, 0, nil, @szExport) then
           begin
            pexport:=allocmem(szexport);
            if CryptExportKey(hUserKey, 0, PRIVATEKEYBLOB, 0, pExport , @szExport) then
               begin
               hFile := CreateFile('UserCert.key',GENERIC_WRITE,FILE_SHARE_READ,nil,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,0);
               if hFile <> INVALID_HANDLE_VALUE then
                    begin
                    WriteFile(hFile, pExport^, szExport, dwWrittenBytes, nil);
                    CloseHandle(hFile);
                    end;
               end;
           end else writeln(inttohex(getlasterror,8));
           //0x8009000B (NTE_BAD_KEY_STATE)
           }
           //
           dwWrittenBytes := 0;
           hFile := CreateFile('UserCert.cer',
                                     GENERIC_WRITE,
                                     FILE_SHARE_READ,
                                     nil,
                                     CREATE_ALWAYS,
                                     FILE_ATTRIBUTE_NORMAL,
                                     0);
           if hFile <> INVALID_HANDLE_VALUE then begin
              WriteFile(hFile, pbEncodedCert^, cbEncodedCert, dwWrittenBytes, nil);
              CloseHandle(hFile);
              result := TRUE;
           end
           else
           begin
              writeln('CreateFile failed with error :'+inttostr(GetLastError));
           end;
        end
        else
        begin
           writeln('CryptSignAndEncodeCertificate failed with error :'+inttostr(GetLastError));
        end;
     end
     else
     begin
        writeln('CryptSignAndEncodeCertificate failed with error :'+inttostr(GetLastError));
     end;
  end_:
     if hUserKey=thandle(-1) then CryptDestroyKey(hUserKey);
     if hUserProv=thandle(-1) then CryptReleaseContext(hUserProv, 0);
     if pPubKeyInfo=nil then FreeMem(pPubKeyInfo);
     if pbEncodedName=nil then FreeMem(pbEncodedName);
     if pbEncodedCert=nil then FreeMem(pbEncodedCert);
     if pbEncodedUsage=nil then FreeMem(pbEncodedUsage);
     //Result := bStatus;
  end;



  function CreateCertificate( pCaContext:wcrypt2.PCCERT_CONTEXT;  szDN:LPCTSTR):BOOL;
var
   bStatus:BOOL = FALSE;
   //hCaProv:PHCRYPTPROV = nil;
   hCaProv:HCRYPTPROV = thandle(-1);
   hCaKey:HCRYPTKEY = thandle(-1);
   pKeyInfo:PCRYPT_KEY_PROV_INFO = nil;
   cbSize:DWORD = 0;
   begin
   if CertGetCertificateContextProperty(wcrypt2.PCCERT_CONTEXT(pCaContext),
                                         CERT_KEY_PROV_INFO_PROP_ID,
                                         nil,
                                         @cbSize) then
   begin
      pKeyInfo := allocmem(cbSize);
      if CertGetCertificateContextProperty(wcrypt2.PCCERT_CONTEXT(pCaContext),
                                         CERT_KEY_PROV_INFO_PROP_ID,
                                         pKeyInfo,
                                         @cbSize) then
      begin
         if CryptAcquireContextW(@hCaProv,
                                 pKeyInfo^.pwszContainerName,
                                 pKeyInfo^.pwszProvName,
                                 pKeyInfo^.dwProvType,
                                 pKeyInfo^.dwFlags) then
         begin
            bStatus := EncodeAndSignCertificate(pCaContext,
                                    hCaProv,
                                    pKeyInfo^.dwKeySpec,
                                    szDN);

            CryptReleaseContext(hCaProv, 0);
         end

         else
            writeln('Failed to acquire CA CSP context. Error:'+inttostr(GetLastError));
      end;


      LocalFree(hlocal(pKeyInfo));
      CryptReleaseContext(hCaProv, 0);
   end;


   result:= bStatus;
end;

  //openssl x509 -inform DER -in usercert.cer -noout -text
  function DoCreateCertificate( storename,caname,cn:string):integer;
var
  hStoreHandle      : HCERTSTORE=nil;
  pCertContext      : wcrypt2.PCCERT_CONTEXT=nil;
  dwLogonCertsCount : DWORD=0;
  pszStoreName      : LPCTSTR;
  Data: array[0..511] of Char;
begin
  hStoreHandle := nil;
  pCertContext := nil;
  dwLogonCertsCount := 0;
  pszStoreName := pchar(storename);
  hStoreHandle := CertOpenSystemStoreA (0, pszStoreName);

  {
  hStoreHandle := CertOpenStore(
       CERT_STORE_PROV_SYSTEM_A,
       0,                      // Encoding type not needed
                               // with this PROV.
       0,                   // Accept the default HCRYPTPROV.
       CERT_SYSTEM_STORE,
                               // Set the system store location in
                               // the registry.
       pszStoreName);                 // Could have used other predefined
                               // system stores
                               // including Trust, CA, or Root.
  }

  if hStoreHandle<>nil then
  begin
      pCertContext := CertEnumCertificatesInStore(hStoreHandle, nil);
      while pCertContext<>nil do
      begin
        if CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil,data, 512) <> 0
           then ; //Writeln('SUBJECT_CERT_NAME: ', data);
         //if IsCACert(pCertContext) then break;
         if data=caname then break;
      pCertContext := CertEnumCertificatesInStore(hStoreHandle, pCertContext);
      end;
      if  pCertContext=nil then writeln('No CA signing certificate found on the '+pszStoreName+' store.')
      else
      begin
         if CreateCertificate(pCertContext, pchar(cn)) then
            writeln('Certificate created successfully.')
         else
            writeln('Failed to create a certificate.');
         CertFreeCertificateContext(pCertContext);
      end;
    CertCloseStore(hStoreHandle, CERT_CLOSE_STORE_FORCE_FLAG);
  end
  else
  begin
    writeln('CertOpenSystemStore failed with error :'+inttostr(GetLastError));
  end;
  Result := 0;
end;

  //convert a decrypted key to raw
  function kull_m_key_capi_decryptedkey_to_raw(publickey:LPCVOID;publickeyLen:DWORD;decrypted:LPCVOID;decryptedLen:DWORD; keyAlg:ALG_ID; var blob:PRSA_GENERICKEY_BLOB; var blobLen:DWORD; var dwProviderType:DWORD):boolean;
  var
       status:BOOL = FALSE;
       keyLen:DWORD;
       ptrDestination, ptrSource:PBYTE;
  begin

  	if pdword(decrypted)^ = $32415352 then //'2ASR'
  	begin
  		keyLen := dword(pointer(nativeuint(decrypted)+2*4)^); //keyLen = ((PDWORD) decrypted)[2];
  		blobLen := sizeof(RSA_GENERICKEY_BLOB) + ((keyLen * 9) div 16);
                blob:=allocmem(bloblen);
                if blob<>nil then
  		begin
  			status := TRUE;
                        //8 bytes
  			blob^.Header.bType := PRIVATEKEYBLOB;
  			blob^.Header.bVersion := CUR_BLOB_VERSION;
  			blob^.Header.reserved := 0;
  			blob^.Header.aiKeyAlg := keyAlg;
                        //12 bytes
  			blob^.RsaKey.magic := dword(decrypted^);
  			blob^.RsaKey.bitlen := keyLen;
  			blob^.RsaKey.pubexp := dword(pointer(nativeuint(decrypted)+4*4)^); //((PDWORD) decrypted)[4];

  			ptrDestination := pointer(nativeuint(blob) + sizeof(RSA_GENERICKEY_BLOB)); //((PBYTE) (*blob)) + sizeof(RSA_GENERICKEY_BLOB);
  			ptrSource := pointer(nativeuint(decrypted)+5*4);; //(PBYTE) ((PDWORD) decrypted + 5);

  			CopyMemory(ptrDestination, ptrSource, keyLen div 8);
  			ptrDestination += keyLen div 8;
  			ptrSource += (keyLen div 8) + 8;
  			CopyMemory(ptrDestination, ptrSource, keyLen div 16);
  			ptrDestination += keyLen div 16;
  			ptrSource += (keyLen div 16) + 4;
  			CopyMemory(ptrDestination, ptrSource, keyLen div 16);
  			ptrDestination += keyLen div 16;
  			ptrSource += (keyLen div 16) + 4;
  			CopyMemory(ptrDestination, ptrSource, keyLen div 16);
  			ptrDestination += keyLen div 16;
  			ptrSource += (keyLen div 16) + 4;
  			CopyMemory(ptrDestination, ptrSource, keyLen div 16);
  			ptrDestination += keyLen div 16;
  			ptrSource += (keyLen div 16) + 4;
  			CopyMemory(ptrDestination, ptrSource, keyLen div 16);
  			ptrDestination += keyLen div 16;
  			ptrSource += (keyLen div 16) + 4;
  			CopyMemory(ptrDestination, ptrSource, keyLen div 8);

  			dwProviderType := PROV_RSA_FULL;
  		end;
  	end;
  	result:= status;
  end;

  //convert a PEM to DER
  function pem_to_der(pPEM:pointer;pemSize:dword;var pDer:pointer;var size:dword):boolean;
  const
  MS_ENH_RSA_AES_PROV:pchar='Microsoft Enhanced RSA and AES Cryptographic Provider';
  CRYPT_SILENT= $00000040;
  var
  rc:boolean;
  begin


    //* back to DER */
    rc := CryptStringToBinaryA(pPEM, pemSize,CRYPT_STRING_BASE64HEADER, nil, @size, nil, nil);
    if rc=false then begin writeln('CryptStringToBinaryA failed');exit;end;

    pDER := AllocMem(size);
    rc := CryptStringToBinaryA(pPEM, pemSize,CRYPT_STRING_BASE64HEADER, pDER, @size, nil, nil);
    if rc=false then begin writeln('CryptStringToBinaryA failed');exit;end;

    //* get private key blob */
    {
        DWORD derSize = 0;
    	rc = CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
    		PKCS_RSA_PRIVATE_KEY, pDER, size, 0, NULL, NULL, &derSize);
    	if (!rc) goto bad;

    	LocalFree(pPrivKeyBLOB);
    	pPrivKeyBLOB = (LPBYTE)LocalAlloc(0, derSize);
    	rc = CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
    		PKCS_RSA_PRIVATE_KEY, pDER, size, 0, NULL, pPrivKeyBLOB, &derSize);
    	if (!rc) goto bad;
        //ready to CryptImportKey
    }

  end;

      //convert binary to base64
    function bin_to_base64(data:pointer;size:dword;var output:string):boolean;
    var
    rc:boolean;
    outputSize:dword=0;
    poutput:LPSTR;
    begin
      result:=false;
      rc := CryptBinaryToStringA(data, size, CRYPT_STRING_BASE64 , nil, outputSize);
      poutput := Allocmem(outputSize);
      rc := CryptBinaryToStringA(data, size, CRYPT_STRING_BASE64 , poutput, outputSize);
      output:=strpas(poutput);
      //
      result:=rc;
    end;

    //convert binary to hex
    function bin_to_hex(data:pointer;size:dword;var output:string):boolean;
    var
    rc:boolean;
    outputSize:dword=0;
    poutput:LPSTR;
    begin
      result:=false;
      rc := CryptBinaryToStringA(data, size, CRYPT_STRING_HEX or CRYPT_STRING_NOCRLF , nil, outputSize);
      poutput := Allocmem(outputSize);
      rc := CryptBinaryToStringA(data, size, CRYPT_STRING_HEX or CRYPT_STRING_NOCRLF , poutput, outputSize);
      output:=strpas(poutput);
      //
      result:=rc;
    end;

  //convert a DER to PEM
  function der_to_pem(data:pointer;size:dword;var pem:string):boolean;
  const
  PKCS_RSA_PRIVATE_KEY= LPCSTR(43);
  var
  rc:boolean;
  //dwPrivateKeyLen:dword;
  //pPrivateDER:LPBYTE;
  pemPrivateSize:dword = 0;
  pPrivatePEM:LPSTR;
  begin
    result:=false;
    //* PEM */
    rc := CryptBinaryToStringA(data, size, CRYPT_STRING_BASE64HEADER, nil, pemPrivateSize);
    pPrivatePEM := Allocmem(pemPrivateSize);
    rc := CryptBinaryToStringA(data, size, CRYPT_STRING_BASE64HEADER, pPrivatePEM, pemPrivateSize);
    pem:=pem+strpas(pPrivatePEM);
    //
    result:=rc;
  end;

  //convert a PVK to PEM
  function pvk_to_pem(data:pointer;var pem:string):boolean;
  const
  X509_CERT                      = LPCSTR(1);
  PKCS_RSA_PRIVATE_KEY= LPCSTR(43);
  var
  rc:boolean;
  dwPrivateKeyLen:dword;
  pPrivateDER:LPBYTE;
  pemPrivateSize:dword = 0;
  pPrivatePEM:LPSTR;
  begin
    result:=false;
    //* DER */
    rc := CryptEncodeObjectEx(X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, data, 0, nil, nil, dwPrivateKeyLen);
    pPrivateDER := Allocmem(dwPrivateKeyLen);
    rc := CryptEncodeObjectEx(X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, data, 0, nil, pPrivateDER, dwPrivateKeyLen);
    if rc=false then begin writeln('CryptEncodeObjectEx failed');exit;end;
    //* PEM */
    rc := CryptBinaryToStringA(pPrivateDER, dwPrivateKeyLen, CRYPT_STRING_BASE64, nil, pemPrivateSize);
    pPrivatePEM := Allocmem(pemPrivateSize);
    rc := CryptBinaryToStringA(pPrivateDER, dwPrivateKeyLen, CRYPT_STRING_BASE64, pPrivatePEM, pemPrivateSize);
    pem:='-----BEGIN RSA PRIVATE KEY-----'+#13#10;
    pem:=pem+strpas(pPrivatePEM);
    pem:=pem+'-----END RSA PRIVATE KEY-----'+#13#10;
    //
    result:=rc;
  end;

  //convert a raw key to a pvk
  //see kuhl_m_crypto_exportRawKeyToFile->kuhl_m_crypto_exportKeyToFile
  function raw_to_pvk(data:pointer;size:dword;keyspec:dword;var pExport:pbyte; var szPVK:DWORD):boolean;
  const
  PVK_FILE_VERSION_0=0;
  PVK_MAGIC=$b0b5f11e; // bob's file
  PVK_NO_ENCRYPT=0;
  //
  PKCS_RSA_PRIVATE_KEY= LPCSTR(43);
  var
  hCapiProv:HCRYPTPROV=0;
  dwprovidertype:dword=PROV_RSA_FULL;
  hCapiKey:HCRYPTKEY=0;
  //
  szExport:dword;
  //szPVK:dword;
  //pExport:pbyte=nil;
  pExt:string;
  pvkHeader:PVK_FILE_HDR; // = (PVK_MAGIC, PVK_FILE_VERSION_0, keySpec, PVK_NO_ENCRYPT, 0, 0);
  //
  hfile_:thandle=thandle(-1);
  //
  rc:boolean;
  dwPrivateKeyLen:dword;
  pPrivateDER:LPBYTE;
  pemPrivateSize:dword = 0;
  pPrivatePEM:LPSTR;
  begin
  result:=false;
  pvkHeader.dwMagic :=PVK_MAGIC;
  pvkHeader.dwVersion :=PVK_FILE_VERSION_0;
  pvkHeader.dwKeySpec :=keySpec;
  pvkHeader.dwEncryptType :=PVK_NO_ENCRYPT;
  pvkHeader.cbEncryptData :=0;
  pvkHeader.cbPvk :=0;

  if CryptAcquireContextA(@hCapiProv, nil, nil, dwProviderType{/*PROV_DSS_DH/* RSA_FULL*/}, CRYPT_VERIFYCONTEXT)=true then
  		begin
  			if CryptImportKey(hCapiProv, pbyte( data), size, 0, CRYPT_EXPORTABLE, @hCapiKey)=false then
  				begin
                                //NTE_BAD_VER(0x80090007L)
                                writeln('CryptImportKey nok:'+inttohex(getlasterror,8));
                                exit;
                                end;
                        //
                        if CryptExportKey(hCapiKey, 0, PRIVATEKEYBLOB, 0, nil, @szExport) then
		        begin
                        szPVK := szExport + sizeof(PVK_FILE_HDR);
                        pExport := Allocmem(szPVK);
                        if pexport<>nil then
                           begin
                           if CryptExportKey(hCapiKey, 0, PRIVATEKEYBLOB, 0, pExport + sizeof(PVK_FILE_HDR), @szExport) then
                              begin
                              {
                              case PBLOBHEADER(pExport + sizeof(PVK_FILE_HDR))^.aiKeyAlg of
                              CALG_RSA_KEYX: pExt := 'keyx.rsa.pvk';
                              CALG_RSA_SIGN: pExt := 'sign.rsa.pvk';
                              CALG_DSS_SIGN: pExt := 'sign.dsa.pvk';
                              else pExt :='pvk';
                              end;
                              }

                              {
                              //* DER */
                              rc := CryptEncodeObjectEx(X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, pExport + sizeof(PVK_FILE_HDR), 0, nil, nil, dwPrivateKeyLen);
                              pPrivateDER := Allocmem(dwPrivateKeyLen);
                              rc := CryptEncodeObjectEx(X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, pExport + sizeof(PVK_FILE_HDR), 0, nil, pPrivateDER, dwPrivateKeyLen);
                              //* PEM */
                              rc := CryptBinaryToStringA(pPrivateDER, dwPrivateKeyLen, CRYPT_STRING_BASE64HEADER, nil, pemPrivateSize);
                              pPrivatePEM := Allocmem(pemPrivateSize);
                              rc := CryptBinaryToStringA(pPrivateDER, dwPrivateKeyLen, CRYPT_STRING_BASE64HEADER, pPrivatePEM, pemPrivateSize);
                              writeln(pPrivatePEM );
                              }
                              result:=true;
                              pvkHeader.cbPvk := szExport;
        		      CopyMemory(pExport, @pvkHeader, sizeof(PVK_FILE_HDR));
                              end; //if CryptExportKey
                           end; //if pexport<>nil then
                        end; //if CryptExportKey
                        //
                        CryptDestroyKey(hCapiKey);
                end; //if CryptAcquireContextA

  end;

  //*********** from nthash-fpc ********************

  function crypto_hash_len( hashId:ALG_ID):dword;
var
	 len:DWORD {$ifdef fpc}= 0{$endif fpc};
	 hProv:HCRYPTPROV=0;
	 hHash:HCRYPTHASH=0;
begin
	if CryptAcquireContext(@hProv, nil, nil, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) then
	begin
		if CryptCreateHash(hProv, hashId, 0, 0, @hHash) then
		begin
			CryptGetHashParam(hHash, HP_HASHVAL, nil, @len, 0);
			CryptDestroyHash(hHash);
		end;
		CryptReleaseContext(hProv, 0);
	end ;
	result:= len;
        log('crypto_hash_len:'+inttostr(result),0);
end;

  function crypto_hash(algid:alg_id;data:LPCVOID;dataLen:DWORD;  hash:lpvoid;hashWanted:DWORD):boolean;
  var
        //status:BOOL {$ifdef fpc}=FALSE{$endif fpc};
    	hProv:HCRYPTPROV;
    	hHash:HCRYPTHASH;
    	hashLen:DWORD;
    	buffer:PBYTE;
    	//PKERB_CHECKSUM pCheckSum;
    	//Context:PVOID;
  begin
  log('**** crypto_hash ****');
    //writeln(inttohex(CALG_SHA1,4));writeln(inttohex(CALG_MD4,4));writeln(inttohex(CALG_MD5,4));
    log('datalen:'+inttostr(datalen));
    result:=false;
    if CryptAcquireContext(@hProv, nil, nil, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) then
    	begin
          log('CryptAcquireContext OK');
    		if CryptCreateHash(hProv, algid, 0, 0, @hHash) then
    		begin
                  log('CryptCreateHash OK');
    			if CryptHashData(hHash, data, dataLen, 0) then
    			begin
                          log('CryptHashData OK');
    				if CryptGetHashParam(hHash, HP_HASHVAL, nil, @hashLen, 0) then
    				begin
                                  log('CryptGetHashParam OK:'+inttostr(hashLen));
                                  buffer:=Pointer(LocalAlloc(LPTR, hashLen));
    					if buffer<>nil  then
    					begin
                                          log('LocalAlloc OK');
    						result := CryptGetHashParam(hHash, HP_HASHVAL, buffer, @hashLen, 0);
                                                  log('CryptGetHashParam:'+BoolToStr(result,true));
                                                  //RtlCopyMemory(pointer(hash), buffer, min(hashLen, hashWanted));
                                                  log('hashLen:'+inttostr(hashLen));
                                                  log('hashWanted:'+inttostr(hashWanted));
                                                  //log(inttohex(hHash,sizeof(pointer)));
                                                  CopyMemory (hash, buffer, min(hashLen, hashWanted));
                                                  //log('HASH:'+ByteToHexaString (buffer^),1);
                                                  //
                                                  LocalFree(thandle(buffer));
    					end;//if(buffer = (PBYTE) LocalAlloc(LPTR, hashLen))
    				end; //CryptGetHashParam
    			end; //CryptHashData
    			CryptDestroyHash(hHash);
    		end; //CryptCreateHash
    		CryptReleaseContext(hProv, 0);
          end; //CryptAcquireContext
          log('**** crypto_hash:'+BoolToStr (result)+' ****');
  end;


end.

