# capi-fpc
playing with crypto api aka capi.
allowing one to export non exportable private key.
<br/><br/>
The following command line options are valid:
<br/><br/>
--export                export to a pfx file, use store and fitler on subject or sha1<br/>
--force                 will hook cpexportkey to export non exportable pvk<br/>
--dumpcert              dump from registry to a cer file, use store and sha1<br/>
--import                import a cert from filename to store<br/>
--mkcert                make a cert, read from store/subject for issuer, and cn<br/>
--enumcerts             enumerate certificates in a store<br/>
--enumstores            enumerate stores<br/>
--delete                use store and filter on subject or sha1<br/>
--pvk2pem               encode/convert a pvk to pem<br/>
--rsa2pvk               export a decrypted rsa blob/raw capi key to pvk<br/>
--rsa2pem               convert a decrypted rsa blob to a base64 pem<br/>
--der2pem               convert a binary cert to base64 pem<br/>
--pem2der               convert a base64 pem to der<br/>
--bin2base64            convert data to base64<br/>
--bin2hex               convert data to hexadecimal<br/>
--hash                  hash data<br/>
--store=<string>        certificate store (default: MY)<br/>
--subject=<string>      subject used when exporting or deleting or making<br/>
--cn=<string>           used by mkcert (default: CN=localhost)<br/>
--sha1=<string>         sha1 used when exporting or deleting<br/>
--profile=<string>      user or machine (default: user)<br/>
--password=<string>     cert password<br/>
--filename=<string>     cert filename<br/>
--data=<string>         anything you want<br/>
--algo=<string>         SHA512 SHA284 SHA256 SHA1 MD5 MD4 MD2<br/>
