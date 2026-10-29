# Studio Essence — Gestão

## Baseline recuperada em 2026-10-29

- Versão visível: **v1.8.1 HF2**.
- Fonte HTML: https://studio-essence-gestao.vercel.app/ (1.042.641 caracteres).
- `index.html`: conteúdo integral da página servida em produção.
- `favicon-marsala.png`: imagem PNG original (32 × 32 px) recuperada do deployment da Vercel e preservada **sem edição**.
- Esses arquivos estão no GitHub; o favicon ainda tem correção visual pendente.
- Não é backup integral: infraestrutura, Edge Functions/APIs, banco, parâmetros e variáveis de ambiente requerem documentação e recuperação próprias.

## Governança

1. Manter a baseline e identificar commits por alteração/hotfix.
2. Não habilitar deploy automático antes de testar estrutura e configuração do projeto.
3. Testar alterações em preview antes de publicar.
4. Preservar capacidade de rollback.
5. Não armazenar segredos nem dados pessoais de clientes no Git.

**Status:** Projeto Vercel existente ainda sem vínculo Git. Nenhum deploy de produção realizado a partir deste repositório.
