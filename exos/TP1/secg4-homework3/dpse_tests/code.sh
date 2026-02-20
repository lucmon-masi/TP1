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
