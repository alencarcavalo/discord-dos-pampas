# Ajustes novos — o que você precisa configurar

## 1. Amigo que só conectava com Radmin VPN (TURN)
Sem TURN, quem está atrás de CGNAT/NAT fechado entra na sala mas não ouve nem fala.
No **Render → Environment**, escolha UMA opção:

**Cloudflare (tem plano gratuito):** Dashboard → Realtime → TURN → criar chave. Depois:
- `CF_TURN_KEY_ID` = ID da chave
- `CF_TURN_API_TOKEN` = token da chave

**Qualquer outro TURN (Metered, ExpressTURN, coturn...):**
- `TURN_URL` = `turn:endereco:3478` (várias separadas por vírgula)
- `TURN_USER` e `TURN_PASS`

Ao subir, o log do Render mostra "TURN da Cloudflare ok". Se a conexão falhar, o app avisa e tenta de novo sozinho.

## 2. Atualização automática do app do Windows
- A tela/recursos do site atualizam sozinhos: basta o deploy no Render e abrir/recarregar.
- O .exe agora se atualiza via GitHub Releases. Para lançar versão nova:
  1. mude "version" em desktop/package.json (ex.: 1.1.0 -> 1.1.1)
  2. faça push: o workflow gera o instalador e publica a Release
- O repositório precisa ser público (privado exige token).
- A 1.1.0 precisa ser instalada uma vez na mão. Depois é automático (aviso verde no topo + Configurações > Atualizações).
- O seletor de janela/tela só existe a partir da 1.1.0.

## 3. Sons de entrar/sair próprios (opcional)
Coloque entrar.mp3 e sair.mp3 (ou .ogg/.wav) em public/sons/. Sem eles, usa os sons sintetizados.

## Eco na transmissão
O Electron só captura o som do PC inteiro (inclui a voz da chamada). O app agora abafa o som da transmissão
só para quem está falando. Dica: com "Saída de áudio" nas configurações, deixe a chamada no fone e o jogo em outro dispositivo.
