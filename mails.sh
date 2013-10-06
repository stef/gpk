#!/bin/sh
 
# reads e-mail addresses (one per row) from `mails.txt` and writes
# e-mail bodies into files inside the `mails` directory, putting the
# e-mail address in the filename, with a `.txt` extension -- these
# can be changed below
# expects your name in $1 - e.g. "jd (John Doe)"
# and your fingerprint in $2 - e.g. "0000 0000 0000 0000 0000 0000 0000 0000"
 
# author: András Veres-Szentkirályi <vsza@vsza.hu>, s@ctrlc.hu
# source code is licensed under MIT, textual content under CC-BY-SA
 
INPUT=mails.txt
OUTDIR=mails
mkdir -p $OUTDIR
 
while read i; do
cat >$OUTDIR/$i.txt <<-MAIL
Hi,
I'm $1 and we both participated in a
keysigning party in the last few months. To sign your UID, I need
to be sure that you control the e-mail address in the UID and the
secret key you signed it with. To prove this, please reply to this
e-mail in a way that it contains this original text, along with
the request identifier string below. Please encrypt the reply with
my public key ($2).
 
Signing it with your key is optional, since you already proved you
possess the private key by decrypting this e-mail.
 
Request ID: $(uuidgen)
 
Upon successful verification, I will sign your UID(s), and if you
allowed/requested it, I will upload the signature to the keyserver.
 
If you have any questions or would like me to perform a similar,
verification, feel free to include these in your reply.
-- 
Regards,
$1
MAIL
done < $INPUT
