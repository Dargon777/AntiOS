"""Published AntiOS starter catalog and pinned Ed25519 verification key.

The indicator data contains NCSC public sector information licensed under OGL v3.0.
See NOTICE for attribution.
"""

PUBLIC_KEY = bytes.fromhex("8f54c4b2c7d99a51c6686a1e46e12e3544c9b675d137233c91ac4e4bbbc4901b")

# Tables 3 and 4 of CISA/FBI AA24-109A identify these exact Windows and ELF samples.
# https://www.cisa.gov/sites/default/files/2024-04/aa24-109a-stopransomware-akira-ransomware_2.pdf
# A newer signed catalog can supersede this supplement.
AKIRA_SUPPLEMENT = (
    "03aa12ac2884251aa24bf0ccd854047de403591a8537e6aba19e822807e06a45",
    "0b5b31af5956158bfbd14f6cbf4f1bca23c5d16a40dbf3758f3289146c565f43",
    "0d700ca5f6cc093de4abba9410480ee7a8870d5e8fe86c9ce103eec3872f225f",
    "2e88e55cc8ee364bf90e7a51671366efb3dac3e9468005b044164ba0f1624422",
    "3d2b58ef6df743ce58669d7387ff94740ceb0122c4fc1c4ffd81af00e72e60a4",
    "40221e1c2e0c09bc6104548ee847b6ec790413d6ece06ad675fff87e5b8dc1d5",
    "5ea65e2bb9d245913ad69ce90e3bd9647eb16d992301145372565486c77568a2",
    "643061ac0b51f8c77f2ed202dc91afb9879f796ddd974489209d45f84f644562",
    "6f9d50bab16b2532f4683eeb76bd25449d83bdd6c85bf0b05f716a4b49584f84",
    "74f497088b49b745e6377b32ed5d9dfaef3c84c7c0bb50fabf30363ad2e0bfb1",
    "a2df5477cf924bd41241a3326060cc2f913aff2379858b148ddec455e4da67bc",
    "e1321a4b2b104f31aceaf4b19c5559e40ba35b73a754d3ae13d8e90c53146c0f",
    "fef09b0aa37cbdb6a8f60a6bd8b473a7e5bffdc7fd2e952444f781574abccf64",
)

# CISA reports and advisories published or updated in 2025 identify these exact
# artifacts as malicious. Keep them as exact-hash confirmations.
# Sources:
# - MAR-25993211.r1.v1 (RESURGE / SPAWNSLOTH)
# - MAR-251132.c1.v1 (credential theft / webshell / PowerShell dropper artifacts)
CISA_2025_SUPPLEMENT = {
    "52bbc44eb451cb5e16bf98bc5b1823d2f47a18d71f14543b460395a1c1b1aeda":
        "RESURGE malware (CISA MAR-25993211)",
    "3526af9189533470bc0e90d54bafb0db7bda784be82a372ce112e361f7c7b104":
        "SPAWNSLOTH malware (CISA MAR-25993211)",
    "60a37499f9b02c203af24c2dfd7fdb3834cea707c4c56b410a7e68376938c4b7":
        "Encoded .NET credential-theft payload (CISA MAR-251132)",
    "92bb4ddb98eeaf11fc15bb32e71d0a63256a0ed826a03ba293ce3a8bf057a514":
        "ASPX credential-theft payload (CISA MAR-251132)",
    "9340bf7378234db5bca0dc5378bf764b6a24bb87a42b05fa21a996340608fbd7":
        "Base64 PowerShell dropper artifact (CISA MAR-251132)",
    "675a10e87c248d0f629da864ba8b7fd92b62323c406a69dec35a0e6e1552ecbc":
        "ASPX webshell payload (CISA MAR-251132)",
    "d9c4dd5a8317d1d83b5cc3482e95602f721d58e3ba624d131a9472f927d33b00":
        "ASPX PowerShell webshell (CISA MAR-251132)",
    # AA25-203A, Table 3: rows explicitly identified as encryptors.
    # https://www.cisa.gov/sites/default/files/2025-07/aa25-203a-stopransomware-interlock-072225.pdf
    "e86bb8361c436be94b0901e5b39db9b6666134f23cce1e5581421c2981405cb1":
        "Interlock ransomware encryptor (CISA AA25-203A)",
    "c733d85f445004c9d6918f7c09a1e0d38a8f3b37ad825cd544b865dba36a1ba6":
        "Interlock ransomware encryptor (CISA AA25-203A)",
    "28c3c50d115d2b8ffc7ba0a8de9572fbe307907aaae3a486aabd8c0266e9426f":
        "Interlock ransomware encryptor (CISA AA25-203A)",
    # AA23-319A, 2025 update, Tables 2 and 3: encryptor and deployment scripts.
    # https://www.cisa.gov/sites/default/files/2025-04/aa23-319a-stopransomware-rhysida-ransomware_2.pdf
    "6633fa85bb234a75927b23417313e51a4c155e12f71da3959e168851a600b010":
        "Rhysida ransomware encryptor (CISA AA23-319A)",
    "97766464d0f2f91b82b557ac656ab82e15cae7896b1d8c98632ca53c15cf06c4":
        "Rhysida ransomware deployment script (CISA AA23-319A)",
    "918784e25bd24192ce4e999538be96898558660659e3c624a5f27857784cd7e1":
        "Rhysida ransomware execution script (CISA AA23-319A)",
    # AA23-352A, 2025 update, Table 2: malware and custom collection tool.
    # https://www.cisa.gov/sites/default/files/2025-06/aa23-352a-stopransomware-play-ransomware_2.pdf
    "47b7b2dd88959cd7224a5542ae8d5bce928bfc986bf0d0321532a7515c244a1e":
        "Play ransomware campaign backdoor (CISA AA23-352A)",
    "453257c3494addafb39cb6815862403e827947a1e7737eb8168cd10522465deb":
        "Play ransomware campaign custom data collector (CISA AA23-352A)",
    "75404543de25513b376f097ceb383e8efb9c9b95da8945fd4aa37c7b2f226212":
        "SystemBC malware executable (CISA AA23-352A)",
}

# NCSC lists these as samples or malware components. Partial-image hashes and
# memory captures are outside the full-file catalog. See NOTICE for licensing.
_NCSC_FAMILY_DIGESTS = {
    # https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Spec-Com-stix.json
    "SpecCom": (
        "0cba1f9fc63bb139d27a99839da8ddad83a40dfd7de8b01a4f6cb516527082d4",
        "14c9c48614e0e105e53014cdfdade738671579a226f7a1345d15662211b45a35",
        "15633871c3630a559dd4e2c7a9b93b02d17dd64ee60a2d7ba340ebd14d13ffac",
        "1c00fd8202a6822257fe34e481c434af58ad0e3e731005a7fec994463c0117a9",
        "27312973aefcfa2511573a28ff42ef12ecbfcf56db42bf4d1371b0a1f1f2732c",
        "295b987c8926399c063ff20d2484477fe31cd2188b604a919dbfa11d9c34b988",
        "3355174b6cd213792be46ed805810acf466d32485a932804331a0dfb219048ea",
        "37c38a857c4a30abb559b0aec5fce7aa54117f7ecddde437fa988dd3527fd6d0",
        "3c30a2075d7ca9b825d81167b79d45ce27a1bf07a0052412359afcdc73fdf51c",
        "4229630102f0b972e9464a48fa67b4f7b1d5def8ad16b8e258523dabb7bda9a8",
        "42e781f5e9c00d09cb5f7697a7b2fc9b04d77cc7978dcca8098f77d57693ca6c",
        "489fca69a622195328302e64e29b6183feac90826dce198432d603202ca4d216",
        "52a53e7e250fa9faa823d26421ca8af42ac40c27bac1d5af65b452c8987cda72",
        "6395c4a8495d3bff293a8a55ca3c5ebf68a616ee212b2a7284610b0a3f7bb5d4",
        "6ffe81c2883c298a65477ba2bc7ba1063315ad6b26f0188e3361d0fa924575ae",
        "784cf7d224974f7e2c43cf10580c42a2521556608a5dd4a11247d09a77f5c8df",
        "78e7c41458e1ddf336f0d2e9625abbdc0b3e86db18aee7377af5711bc927da35",
        "7c25a5a88bfcc0ea7af287921860c6ab6b88b90042738650386c334bdef5b62b",
        "83bc8f011cba273c9c0dd2070cad429664ea5cdef05387edfad7e0cd6a389b66",
        "96fa3b2466ab06fbaf17f0d19507fb5b6614d1648d9811904a04d017b38af74a",
        "9a3c2ba8ddbeffcb86e53f5193fe74747d7df2ca33ba839b1b23d04d0d5869e4",
        "ab1983217880dad9c0481aab5b06e1fe4b9caaf8d56d8a03bf794aca18f2e4c6",
        "b66104b4eb7d9cb169707289a1a0deac7ad8e262799b42d142bb5c009dcba4b5",
        "c0082f8f1e49c0805c4eaacf5cf5b99ae30eeea585fd77cbd50904927052a18c",
        "d31e440e0d6f98209a9c9c7b4e332f417e41030a4bf4a4ae99d326cec24807af",
        "e683c86fd40eac23bc6435f479518ea5d80f90da294d5ad21d024dd7acc8a6ac",
        "e7a5205bd0d941a7b6c88d31f3b958c890a4f09a49ec8a3a45f4bedaf194afeb",
        "e9013f35ce11fc4c5eb2c21827bdc459202d362365d6ea5b724dee4fe0088bd1",
        "fc3cdc3932d69c05c735040245f94fafe22b79cd865bb7d23c4364a3f4e8c774",
        "ff1055da48829a69709702f1b44f5af0aa9be013bdc7fdf14db9dc66180d476d",
        "ff97e35aec84882611d56dc5758e7dedd4839e326e5708d6d5ae4dbd296dd62d",
    ),
    # https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Infinite-Second-stix.json
    "Infinite Second / ComRAT": (
        "27fb6e28589ddff239d2616fde8169204da3f8365b9670e68f733424ecab93fe",
        "9a3c57b080cb7b55d56b263a0bb2de592681e78716d025b3cdc895ee2dc144a1",
        "b93484683014aca8e909c9b5648d8f0ac21a45d0c193f6ca40f0b01d2464c1c4",
        "d532610528ad75d80c17f0372c5af8d2e417e0e2e08a055bf9923b71c149c51c",
        "e209d07f8992892bf4776c897a8f054849b12464d9f58bcb78602217b3fd98bc",
    ),
    # https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Devil-Bait-stix.json
    "Devil Bait": (
        "a6f9043627f8be2452153b5dbf6278e9b91763c3b5c2aea537a859e0c8c6b504",
        "fa71eee906a7849ba3f4bab74edb577bd1f1f8397ca428591b4a9872ce1f1e9b",
    ),
    # https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Busy-Buzzard-indicators.csv
    "Busy Buzzard": (
        "6cf6d1a9caee970bcb393a085d1dbb1f01a81fa684f6faf7ddbf0253302e1a4e",
        "bd6992029c879b74b255aeb3549b8da487aff75d3f614832c23b4cd3717a067b",
    ),
    # https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Cyclops-Blink-indicators.csv
    "Cyclops Blink": (
        "4e69bbb61329ace36fbe62f9fb6ca49c37e2e5a5293545c44d155641934e39d1",
        "ff17ccd8c96059461710711fcc8372cfea5f0f9eb566ceb6ab709ea871190dc6",
    ),
}
NCSC_SUPPLEMENT = {
    digest: f"{family} (NCSC)"
    for family, digests in _NCSC_FAMILY_DIGESTS.items()
    for digest in digests
}


BUNDLED_PACKAGE = b"""
{
  "catalog": {
    "published": "2026-11-10",
    "schema": 1,
    "sha256": {
      "03563997eb552d8a7278aa6aecffd05717dc36a1480795d06685ba7f1df3675f": {
        "label": "Rhythmic Parry",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Rhythmic-Parry-indicators.csv",
        "source_date": "2022-01-10"
      },
      "0df3b6e2535f8bb564183ab4e5e47d9b30ffc0204cc5bda1bae8984cdc418410": {
        "label": "Jolly Jellyfish",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Jolly-Jellyfish-indicators.csv",
        "source_date": "2021-12-15"
      },
      "12a29373c1f493f7757b755099bde4770c310af3fde376176b6d792cd1c5e150": {
        "label": "Goofy Guineapig",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Goofy-Guineapig-indicators.csv",
        "source_date": "2022-12-13"
      },
      "14930488158df5fca4cba80b1089f41dc296e19bebf41e2ff6e5b32770ac0f1e": {
        "label": "COLDSTEEL",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Cold-Steel-indicators.csv",
        "source_date": "2023-01-31"
      },
      "190293440fce95f45eb8bf5d40334b41dd68c79578d06fe9b34670298daea7f3": {
        "label": "Umbrella Stand",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/ncsc-mar-umbrella-stand-indicators.csv",
        "source_date": "2025-06-18"
      },
      "19cef7f32e42cc674f7c76be3a5c691c543f4e018486c29153e7dde1a48af34c": {
        "label": "Goofy Guineapig",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Goofy-Guineapig-indicators.csv",
        "source_date": "2022-12-13"
      },
      "22a8b4a7c7a467ea7fcf0a3930c99ecb482095093839683b400f58e2cdda176f": {
        "label": "Cheeky Chipmunk",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Cheeky-Chipmunk-indicators.csv",
        "source_date": "2022-01-24"
      },
      "27e7d2054a68510c974add24f33c1c7ef06ef68028cca021cd6b5e67363e2bea": {
        "label": "Cheeky Chipmunk",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Cheeky-Chipmunk-indicators.csv",
        "source_date": "2022-01-24"
      },
      "2d19e015412ef8f8f7932b1ad18a5992d802b5ac62e59344f3aea2e00e0804ad": {
        "label": "Infamous Chisel",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Infamous-Chisel-indicators.csv",
        "source_date": "2023-08-31"
      },
      "31a8a2762b42a1fe4be2aed9d112a169f791bd86a85e68d738aea51312096442": {
        "label": "Damascened Peacock",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/ncsc-mar-damascened-peacock-indicators.csv",
        "source_date": "2025-04-11"
      },
      "338f8b447c95ba1c3d8d730016f0847585a7840c0a71d5054eb51cc612f13853": {
        "label": "Infamous Chisel",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Infamous-Chisel-indicators.csv",
        "source_date": "2023-08-31"
      },
      "3cf2de421c64f57c173400b2c50bbd9e59c58b778eba2eb56482f0c54636dd29": {
        "label": "Infamous Chisel",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Infamous-Chisel-indicators.csv",
        "source_date": "2023-08-31"
      },
      "454e6c3d8c1c982cd301b4dd82ec3431935c28adea78ed8160d731ab0bed6cb7": {
        "label": "Cheeky Chipmunk",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Cheeky-Chipmunk-indicators.csv",
        "source_date": "2022-01-24"
      },
      "4a43fa8a3305c2a17f6a383fb68f02515f589ba112c6e95f570ce421cc690910": {
        "label": "Jolly Jellyfish",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Jolly-Jellyfish-indicators.csv",
        "source_date": "2021-12-15"
      },
      "50838e12e58a2d96b1a2ebdb53a25151cc22cbd458dba49fcb355ccfc82e0e63": {
        "label": "COLDSTEEL",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Cold-Steel-indicators.csv",
        "source_date": "2023-01-31"
      },
      "5866e1fa5e262ade874c4b869d57870a88e6a8f9d5b9c61bd5d6a323e763e021": {
        "label": "Infamous Chisel",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Infamous-Chisel-indicators.csv",
        "source_date": "2023-08-31"
      },
      "591d60c1d356da827a26f4141fa431d3663af91746d5371014695b1c89bac2b2": {
        "label": "Umbrella Stand",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/ncsc-mar-umbrella-stand-indicators.csv",
        "source_date": "2025-06-18"
      },
      "5c5323bd17fd857a0e77be4e637841dad5c4367a72ac0a64cc054f78f530ba37": {
        "label": "Infamous Chisel",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Infamous-Chisel-indicators.csv",
        "source_date": "2023-08-31"
      },
      "6455de74ae15071fa98f18cdbc3148c967755e69df7dee747bc31d0387751162": {
        "label": "Pygmy Goat",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/ncsc-mar-pygmy-goat-indicators.csv",
        "source_date": "2024-10-30"
      },
      "6a3abc19f324a475d4ce01fcc69797fc90e1a47970ed90e9cb01f540f3000b4e": {
        "label": "Umbrella Stand",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/ncsc-mar-umbrella-stand-indicators.csv",
        "source_date": "2025-06-18"
      },
      "6b52fd7ee1442b4ed2c675f958a42a6c793bfe14a75de0988c4381367284f085": {
        "label": "Busy Buzzard",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Busy-Buzzard-indicators.csv",
        "source_date": "2022-03-25"
      },
      "6c121f2b2efa6592c2c22b29218157ec9e63f385e7a1d7425857d603ddef8c59": {
        "label": "Smooth Operator",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Smooth-Operator-indicators.csv",
        "source_date": "2023-06-29"
      },
      "722fa0c893b39fef787b7bc277c979d29adc1525d77dd952f0cc61cd4d0597cc": {
        "label": "Cheeky Chipmunk",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Cheeky-Chipmunk-indicators.csv",
        "source_date": "2022-01-24"
      },
      "7ce2909bf205c1a574ac3dcac5891e31aa59dd4cad6c41d7159ad017c837903c": {
        "label": "COLDSTEEL",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Cold-Steel-indicators.csv",
        "source_date": "2023-01-31"
      },
      "804dc9c037e9d0e5426cb1f0df8dde61cd43cf6ea4c27cf526c2d6ac50ba3e95": {
        "label": "Damascened Peacock",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/ncsc-mar-damascened-peacock-indicators.csv",
        "source_date": "2025-04-11"
      },
      "823b079c75f4e6a5905d9eea9a60c62e1f0995bfc25764d1ba0407a5bd78c962": {
        "label": "Pygmy Goat",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/ncsc-mar-pygmy-goat-indicators.csv",
        "source_date": "2024-10-30"
      },
      "83030f299a776114878bcd2ade585d97836ef4ddb6943cb796be2c88bcb83a83": {
        "label": "Busy Buzzard",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Busy-Buzzard-indicators.csv",
        "source_date": "2022-03-25"
      },
      "8bacd5df99476328321a7e8e2fc0124c20f7a7ebf3e8f151c050387038515b70": {
        "label": "Umbrella Stand",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/ncsc-mar-umbrella-stand-indicators.csv",
        "source_date": "2025-06-18"
      },
      "968d26244b3243a25c66170900b815123469822385cab610267c3a65e755d1ba": {
        "label": "COLDSTEEL",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Cold-Steel-indicators.csv",
        "source_date": "2023-01-31"
      },
      "97f66bcdd73917a8b59d9a1dcac21a58936bcaf91e757a9dfb8e5c320af40f56": {
        "label": "Goofy Guineapig",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Goofy-Guineapig-indicators.csv",
        "source_date": "2022-12-13"
      },
      "9d6e14cd244f6c49e11d2b47f12116b5848aaed7a6aaa218fb023b33f7c12a3b": {
        "label": "Busy Buzzard",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Busy-Buzzard-indicators.csv",
        "source_date": "2022-03-25"
      },
      "a64b41e98e3e1066f41fbff5d4f99f6d34b792d35fe2be7e5d9fa8f3f8b93739": {
        "label": "Umbrella Stand",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/ncsc-mar-umbrella-stand-indicators.csv",
        "source_date": "2025-06-18"
      },
      "a64fa9f1c76457ecc58402142a8728ce34ccba378c17318b3340083eeb7acc67": {
        "label": "Smooth Operator",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Smooth-Operator-indicators.csv",
        "source_date": "2023-06-29"
      },
      "a7e9e2bec3ad283a9a0b130034e822c8b6dfd26dda855f883a3a4ff785514f97": {
        "label": "Jolly Jellyfish",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Jolly-Jellyfish-indicators.csv",
        "source_date": "2021-12-15"
      },
      "a9fa8e8609872cdcea241e3aab726b02b124c82de4c77ad3c3722d7c6b93b9b5": {
        "label": "COLDSTEEL",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Cold-Steel-indicators.csv",
        "source_date": "2023-01-31"
      },
      "b75208393fa17c0bcbc1a07857686b8c0d7e0471d00a167a07fd0d52e1fc9054": {
        "label": "Small Sieve",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Small-Sieve-indicators.csv",
        "source_date": "2022-01-27"
      },
      "bf090cf7078414c9e157da7002ca727f06053b39fa4e377f9a0050f2af37d3a2": {
        "label": "Small Sieve",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Small-Sieve-indicators.csv",
        "source_date": "2022-01-27"
      },
      "ca9bcf268330a4fffcec025920514e0071651c35895b15b2f1dab8813c8b8e99": {
        "label": "Busy Buzzard",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Busy-Buzzard-indicators.csv",
        "source_date": "2022-03-25"
      },
      "d86f7d63bf8faa7070ba096523cf114947b55570dc50b0583797c9897ba3559c": {
        "label": "Cheeky Chipmunk",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Cheeky-Chipmunk-indicators.csv",
        "source_date": "2022-01-24"
      },
      "e0b107be8034976f6e91cfcc2bbc792b49ea61a071166968fec775af28b1f19c": {
        "label": "SparrowDoor",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Sparrow-Door-indicators.csv",
        "source_date": "2022-02-28"
      },
      "e6bbc33815b9f20b0cf832d7401dd893fbc467c800728b5891336706da0dbcec": {
        "label": "Smooth Operator",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Smooth-Operator-indicators.csv",
        "source_date": "2023-06-29"
      },
      "e92d4e58dfae7c1aadeef42056d5e2e5002814ee3b9b5ab1a48229bf00f3ade6": {
        "label": "COLDSTEEL",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Cold-Steel-indicators.csv",
        "source_date": "2023-01-31"
      },
      "ef466e714d5250e934e681bda6ebdecd314670bb141f12a1b02c9afddbd93428": {
        "label": "Infamous Chisel",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Infamous-Chisel-indicators.csv",
        "source_date": "2023-08-31"
      },
      "f0449c41bc3eebb8ea025fafc5b0cd1fcbe9a2d80c447ecc00cf3cab43e1c311": {
        "label": "Jolly Jellyfish",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Jolly-Jellyfish-indicators.csv",
        "source_date": "2021-12-15"
      },
      "f19bb3b49d548bce4d35e9cf83fba112ef8e087a422b86d1376a395466fdff2d": {
        "label": "SparrowDoor",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Sparrow-Door-indicators.csv",
        "source_date": "2022-02-28"
      },
      "f21a9c69bfca6f0633ba1e669e5cf86bd8fc55b2529cd9b064ff9e2e129525e8": {
        "label": "Jolly Jellyfish",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Jolly-Jellyfish-indicators.csv",
        "source_date": "2021-12-15"
      },
      "ff3ec235c80df9e9b340cdddc4d253b2c495446dd27158f9afb88d9b604a1dac": {
        "label": "Rhythmic Parry",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Rhythmic-Parry-indicators.csv",
        "source_date": "2022-01-10"
      }
    },
    "version": 3
  },
  "signature": "15f85d1a2226ba10d1b6a51fbb1c49f7d0b96e69c7fce68c52a9d2165b02643fe77363906c5d7b1d0b4272ba9369979ee1cb28b453c6ebac76a9698cfeadd401"
}
"""
