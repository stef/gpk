#!/usr/bin/ksh -x

KeyType=RSA
masterkeysize=1024
username=joe
usercmt="test"
email="j@example.com"
masterexpire=0

function createkey {
gpg -q --gen-key --batch <(
    cat <<EOF
Key-Type: $KeyType
Key-Length: $masterkeysize
Key-Usage: sign
EOF
    [[ -n "$username" ]] && echo "Name-Real: $username"
    [[ -n "$usercmt" ]] && echo "Name-Comment: $usercmt"
    [[ -n "$email" ]] && echo "Name-Email: $email"
    cat <<EOF
Expire-Date: $masterexpire
%secring $secring
%pubring $pubring
%commit
EOF
)
}

mkdir -p "$1" || exit 1
chmod 700 "$1"

pubring="$1/pubring.pgp"
secring="$1/secring.pgp"

#startdate=0                              # all
startdate=$(date -d "3 months ago" "+%s") # quite fresh, burns lot's of precious entropy!

line=""
while true; do
    createkey
    python ./genkeyid.py $pubring $startdate 2>$1/snapshots | grep --line-buffered --color -i "$2" | tee $1/fps | read line
    [[ -n "$line" ]] && break
done

[[ -z "$line" ]] && exit 1
echo $line 
python ./setfp.py $secring $pubring $(echo "$line" | cut -d' ' -f2)
