Ce protocole est un logiciel, incluant une interface graphique sous next js, un backend en Rust sous Tauri et une base de données sqlite3 qui stocke les secrets (données dont l'utilisateur souhaite crypter). Il combine plusieurs primitives cryptographiques telles que AEAD mode GCM, Argon 2, SHA-256, ces primitives réunis assure l'intégrité et la confidentialité des données. Parmis les fonctionnalités nous retrouverons:

**F1- Authentification:** 
Pour utiliser le logiciel, l’utilisateur devra s'authentifier en fournissant son nom d’utilisateur et son mot de passe.

**F2 - Gestionnaire de secret:**
Après authentification l’utilisateur arrive dans la page ou il pourra gérer l'ensemble des secrets stocker dans la base de données, chaque caractère du secret est caché par un étoile. Dans le gestionnaire l’utilisateur pourra voir le texte d’origine (décrypter), ajouter, copier, supprimer et modifier un secret.

## Sécurité
Les primitives cryptographiques citées ci-dessus sont introduites dans le protocole et utilisées pour effectuer les opérations suivante:

1. Dérivations des clés:
Le mot de passe dans le système est nommé la “Master Key”, c’est une donnees qui est hashé avec la fonction de hashage Argon 2 pour générer 2 nouvelles clés soit K1 et K2 qui sont utilisés pour le cryptage et le décryptage de certains paramètres sensibles et tous les secrets.

2. Cryptage de paramètres sensibles:
Parmi les paramètres utilisés par AEAD-GCM un seul paramètre est crypté, soit la DA (Data Associated), c’est un paramètre qui permet d’assurer l'intégrité des secrets, elle est crypté sous AEAD-GCM avec la clé dérivée K1, un nonce unique pour déverrouiller ce paramètre et sans DA. Si un attaquant retrouve ce paramètre, il pourra facilement retrouver le texte d’origine et modifier les secrets. Les paramètres comme les nonces uniques pour chaque secret et le nonce pour déverrouiller le paramètre DA sont stockés dans la base de données sans être cryptés.

3. Les secrets:
Comme expliqué plus tôt, les secrets sont des informations dont l’utilisateur souhaite crypter. Lorsqu’un utilisateur ajoute un secret, la clé dérivée K2 et la DA décrypter seront utilisées dans la primitive AEAD-GCM pour la crypter. Lorsque l’utilisateur décrypte l’information, elle sera visible pendant 15 secondes, après elle sera de nouveaux crypter. Lors d’une modification d’un secret l’utilisateur ne verra pas le secret, la nouvelle modification vient écraser la précédente sans une opération de décryptage du secret précédent.

4. La base de données:
Dans la base de données, les informations les moins sensibles comme le nonce sont stockées sans être cryptées mais les informations plus sensibles sont stockées en étant cryptées comme les secrets et la DA.

5. La mémoire:
Pour éviter qu’un logiciel malveillant puisse facilement retrouver les informations décryptées ou cryptées dans la mémoire de la machine, les données de base de données, les données seront très peu stockées dans la mémoire.

