éléves : Xavier Dujardin et Lucas Monis 

# Exo 1
## Actor: Belgian Education Authority
```bash
# cwd: /be_education_authority/private/

# Générer la clé privée ECDSA sur la courbe prime256v1 (P-256)
openssl ecparam -name prime256v1 -genkey -noout -out be_ea_key.pem

# Générer le certificat X.509 auto-signé, valide 10 ans, signé avec SHA-1
openssl req -new -x509 \
  -key be_ea_key.pem \
  -sha1 \
  -days 3652 \
  -out be_ea_cert.pem \
  -subj "/C=BE/ST=Hainaut/L=Charleroi/O=Belgian Education Authority/CN=Belgian Education Authority DSC01"

```

# Exo 2
setup:
```bash
# cwd: /
cp be_education_authority/private/be_ea_cert.pem central_education_authority/tmp/
```

## Actor: Central Education Authority
``` bash
# cwd: /central_education_authority/tmp/

# Calculer le fingerprint SHA-1 du certificat, sans ':' et en majuscule

openssl x509 -in be_ea_cert.pem -noout -fingerprint -sha1 \
  | cut -d= -f2 | tr -d ':' | tr 'a-f' 'A-F' > dscfingerprint.txt

# Charger le fingerprint dans une variable
FPR=$(cat dscfingerprint.txt)

# Publier le certificat dans le dépôt public avec le nom DSCFINGERPRINT.pem
cp be_ea_cert.pem ../pubrepo/"${FPR}.pem"
```


# Exo 3
## Actor: HE2B School
```bash
# cwd: /he2b_school/tmp/

ROLL=49441

cat > ${ROLL}.txt <<EOF
Monis
Lucas
${ROLL}
BE
Haute Ecole Bruxelles-Brabant
2021-09-15
2022-09-14
EOF
```


# Exo 4
setup:
```bash
# cwd: /
cp he2b_school/tmp/49441.txt be_education_authority/tmp/
```

## Actor: Belgian Education Authority
```bash
# cwd: /be_education_authority/tmp/

ROLL=49441

openssl dgst -sha1 -sign ../private/be_ea_key.pem ${ROLL}.txt \
  | base64 | tr -d '\n' > ${ROLL}.signature.txt

openssl x509 -in ../private/be_ea_cert.pem -noout -fingerprint -sha1 \
  | cut -d= -f2 | tr -d ':' | tr 'a-f' 'A-F' > ${ROLL}.dscfingerprint.txt
```


# Exo 5
setup:
```bash
# cwd: /
cp be_education_authority/tmp/12345.{signature,dscfingerprint}.txt he2b_school/tmp/
```

## Actor: HE2B School
```bash
# cwd: /he2b_school/tmp/

ROLL=49441

cat ${ROLL}.txt > ../dpse/${ROLL}.dpse.txt

printf "%s\n" "$(cat ${ROLL}.signature.txt)" >> ../dpse/${ROLL}.dpse.txt

printf "%s\n" "$(cat ${ROLL}.dscfingerprint.txt)" >> ../dpse/${ROLL}.dpse.txt
```

# Exo 6

## Actor: HE2B School

```bash
# cwd: /he2b_school/dpse/

ROLL=49441
FILE=${ROLL}.dpse.txt

# Extraire le message (lignes 1 à 7)
head -n 7 "$FILE" > ${ROLL}.msg.txt

# Extraire la signature base64 (ligne 8)
sed -n '8p' "$FILE" > ${ROLL}.sig.b64

# Décoder la signature en binaire
base64 -d ${ROLL}.sig.b64 > ${ROLL}.sig.bin

# Vérifier la signature avec le DSC de la Belgian Education Authority
openssl dgst -sha1 \
  -verify <(openssl x509 -in ../../be_education_authority/private/be_ea_cert.pem -pubkey -noout) \
  -signature ${ROLL}.sig.bin \
  ${ROLL}.msg.txt
```


# Exo 7

## Actor : Verifier

```bash
# cwd: /dpse_tests

for ROLL in 386562 714095 794055 879919 895718; do
  FILE=${ROLL}.txt

  echo "== Checking DPSE ${ROLL} =="

  # 1) Vérifier que le fichier DPSE existe
  if [ ! -f "$FILE" ]; then
    echo "${ROLL} INVALID, DPSE file missing"
    echo
    continue
  fi

  # 2) Extraire message, signature, fingerprint
  head -n 7 "$FILE" > ${ROLL}.msg.txt
  sed -n '8p' "$FILE" > ${ROLL}.sig.b64
  sed -n '9p' "$FILE" > ${ROLL}.dscfingerprint.txt

  # Vérifier que signature et fingerprint existent
  if [ ! -s ${ROLL}.sig.b64 ]; then
    echo "${ROLL} INVALID, missing signature line"
    echo
    continue
  fi

  if [ ! -s ${ROLL}.dscfingerprint.txt ]; then
    echo "${ROLL} INVALID, missing dscfingerprint line"
    echo
    continue
  fi

  # 3) Décoder la signature
  if ! base64 -d ${ROLL}.sig.b64 > ${ROLL}.sig.bin 2>/dev/null; then
    echo "${ROLL} INVALID, signature is not valid base64"
    echo
    continue
  fi

  # 4) Récupérer le DSC correspondant depuis le pubrepo racine
  FPR=$(cat ${ROLL}.dscfingerprint.txt)
  DSC=../pubrepo/${FPR}.pem

  if [ ! -f "$DSC" ]; then
    echo "${ROLL} INVALID, DSC ${FPR}.pem not found in pubrepo"
    echo
    continue
  fi

  # 5) Vérifier la signature (ECDSA + SHA-256)
  if openssl dgst -sha256 \
       -verify <(openssl x509 -in "$DSC" -pubkey -noout) \
       -signature ${ROLL}.sig.bin \
       ${ROLL}.msg.txt >/dev/null 2>&1; then
    echo "${ROLL} VALID"
  else
    echo "${ROLL} INVALID, signature does not match"
  fi

  echo
done
```
