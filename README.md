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

## Backlog — próximo hotfix financeiro

**Conciliação de comissões geradas vs. fechamentos pagos (sem alterar histórico financeiro automaticamente)**

- Comparar o agregado do dashboard e o detalhamento do card com os fechamentos e comissões por atendimento.
- Priorizar fechamento pago como fonte de referência histórica; comissões abertas seguem o cálculo atual.
- Preservar auditoria e eventuais ajustes intencionais, evitando duplicidade e reprocessamento de caixa.
- Divergências encontradas em 2026-10-29, por profissional: Victoria +R$ 22,00 (63 vs. 85), Daniele +R$ 37,50, Nana -R$ 24,19, Pamela -R$ 8,50 em 6 itens; sinal = fechamento menos atendimento.
- Validar os totais de dashboard e reconciliação antes de implantar uma correção financeira.

**HF4 — Dashboard:** gráfico Receitas × Saídas em visão mensal janeiro–dezembro, com ano próprio, sem depender do filtro De/Até do dashboard. Mudança restrita à apresentação do gráfico.

## HF5 — comissões reconhecidas no dashboard

- API apiDashboardV180 e apiCommissionGeneratedDetailV181 usarão comissoes_itens.valor_comissao dos fechamentos PAGO, pareados por ID do item, como referência histórica; itens sem fechamento pago manterão o valor_comissao da origem.
- Filtrar serviços/vendas ativos no período solicitado e não somar fechamentos novamente; evitar dupla contagem.
- Não modificar tabelas, fechamentos, vales, movimentos de caixa nem status financeiros.
- Validar divergências de outubro (Victoria, Daniele, Nana, Pamela) e igualdade entre card e composição.
