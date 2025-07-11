# Product Requirements Document (PRD): Refatoração eZpZ para Fish Shell

## 1. Introdução

Este PRD detalha o processo de refatoração do script de hacking `ezpz.sh` (atualmente em Zsh) para o Fish Shell. O objetivo principal é melhorar a modularidade, a legibilidade, a manutenibilidade e a performance do conjunto de ferramentas, além de adaptá-lo ao ambiente Fish. A refatoração será conduzida de forma iterativa, uma função por vez, com o Cursor atuando como um assistente interativo para cada etapa.

## 2. Escopo do Projeto

### 2.1. Funcionalidades a Serem Refatoradas (Funções)

Cada uma das seguintes funções do `ezpz.sh` original será refatorada individualmente para o Fish Shell:

*   `loot`
*   `secretsparse`
*   `netscan`
*   `webscan`
*   `checkvulns`
*   `adscan`
*   `startresponder`
*   `testcreds`
*   `enumdomain`
*   `enumuser`
*   `enumshares`
*   `enumsql`

### 2.2. Funcionalidade Removida/Alterada

*   A função `get_auth()` será **descontinuada** como um módulo centralizado. A lógica de parsing de argumentos de autenticação (`-u`, `-p`, `-H`, `-k`, `-t`, `-d`, etc.) e a construção das strings de autenticação para `nxc` (NetExec) e ferramentas Impacket (ex: `GetUserSPNs.py`) serão movidas e adaptadas para **dentro de cada função que as utiliza**. Isso garante que cada função trate a autenticação de forma específica e otimizada para suas necessidades.

### 2.3. Não Escopo

*   Adição de novas funcionalidades não presentes no `ezpz.sh` original (nesta fase inicial de refatoração).
*   Otimizações de algoritmos internos das ferramentas de segurança subjacentes (nmap, nxc, etc.).

## 3. Arquitetura Proposta (Fish Shell)

A suíte `ezpz` refatorada seguirá uma arquitetura modular e idiomática para o Fish Shell.

### 3.1. Estrutura de Diretórios

Os scripts refatorados serão mantidos em um repositório Git. Dentro do repositório, haverá uma subpasta dedicada às funções:

```
ezpz/
├── functions/
│   ├── ezpz.fish           # O script dispatcher principal (o que o usuário chama)
│   ├── ezpz_loot.fish      # Função refatorada para 'loot'
│   ├── ezpz_secretsparse.fish
│   ├── ezpz_netscan.fish
│   ├── ezpz_webscan.fish
│   ├── ezpz_checkvulns.fish
│   ├── ezpz_adscan.fish
│   ├── ezpz_startresponder.fish
│   ├── ezpz_testcreds.fish
│   ├── ezpz_enumdomain.fish
│   ├── ezpz_enumuser.fish
│   ├── ezpz_enumshares.fish
│   ├── ezpz_enumsql.fish
│   └── # Outras funções auxiliares ou de cores se necessário
└── old/
│   └── ezpz.sh             # O script Zsh original para referência
└── README.md
└── LICENSE
└── .git/
```

### 3.2. Carregamento de Funções (Lazy Loading)

O diretório `ezpz/functions/` será adicionado à variável `$fish_function_path` no `~/.config/fish/config.fish` do usuário:

```fish
# Adiciona o diretório de funções do EZPZ ao fish_function_path
# Isso permite que o Fish encontre e auto-carregue as funções
# Ajuste o caminho para onde seu repositório está clonado.
set -gx fish_function_path "$HOME/path/to/ezpz/functions" $fish_function_path
```

Esta configuração permitirá que o Fish carregue as funções sob demanda (lazy loading), melhorando o tempo de inicialização do shell e o uso de memória.

### 3.3. Dispatcher (`ezpz.fish`)

O arquivo `ezpz.fish` conterá a função principal `ezpz`. Suas responsabilidades incluem:

*   Exibir a arte ASCII e o menu de ajuda geral quando chamado sem argumentos (`ezpz`).
*   Receber o primeiro argumento como o nome do subcomando (ex: `netscan`, `loot`).
*   Validar se o subcomando existe como uma função `ezpz_<subcomando>`.
*   Chamar a função `ezpz_<subcomando>` correspondente, passando os argumentos restantes.
*   Tratar comandos desconhecidos com uma mensagem de erro clara.

### 3.4. Funções Individuais (`ezpz_<comando>.fish`)

Cada arquivo `ezpz_<comando>.fish` conterá a definição da função `ezpz_<comando>`. Suas responsabilidades incluem:

*   Definir a função com a sintaxe `function ezpz_comando ... end`.
*   Implementar a lógica específica do comando, convertida de Zsh para Fish.
*   **Tratar seus próprios argumentos** (obrigatórios, opcionais, flags). O `argparse` do Fish é uma ferramenta poderosa para isso.
*   **Gerenciar a lógica de autenticação:** Se a função precisar de autenticação, ela fará o parsing dos argumentos de autenticação (`-u`, `-p`, `-H`, `-k`) e construirá as variáveis ou strings necessárias para as chamadas de `nxc` ou Impacket **internamente**, sem depender de um `get_auth()` global.
*   Realizar as verificações de pré-requisitos (`command -v tool`).
*   Gerenciar arquivos temporários usando `mktemp` e `trap`.
*   Fornecer sua própria mensagem de `usage` e ajuda detalhada quando chamada com `--help` ou `-h`.
*   Utilizar o novo esquema de colorização de output.

## 4. Princípios de Refatoração

### 4.1. Refatoração Iterativa

O processo será conduzido função por função. Não avançaremos para a próxima função até que a atual esteja razoavelmente refatorada e compreendida.

### 4.2. Tratamento de Autenticação (`get_auth` Replacement)

A lógica do `get_auth` será absorvida pelas funções individuais. Cada função que exige autenticação (`loot`, `checkvulns`, `enumdomain`, `testcreds`, `enumuser`, `enumshares`) será responsável por:

*   Receber os argumentos de autenticação relevantes (ex: `-u`, `-p`, `-H`, `-k`).
*   Extrair o username, password/hash, e determinar o tipo de autenticação.
*   Derivar o domínio (se aplicável, de `-d` ou do próprio username `DOMAIN\user`).
*   Construir a string de autenticação (`-u user -p pass` ou `-u user -H hash`) e parâmetros específicos para **cada chamada de ferramenta** (`nxc`, `secretsdump.py`, `impacket` tools como `GetNPUsers.py`, `GetUserSPNs.py`, `findDelegation.py`, `pre2k`).
*   A sincronização de tempo para Kerberos (`sudo ntpdate`) também será reavaliada e colocada onde for mais apropriado para cada função que a use.

### 4.3. Colorização de Output

Todos os códigos ANSI raw (`\033[...m`) serão substituídos pelo comando `set_color` do Fish. O Cursor deverá usar uma abordagem consistente, preferencialmente via funções auxiliares (ver seção 6).

### 4.4. Gerenciamento de Arquivos Temporários

A prática de usar `mktemp` para criar arquivos temporários e `trap 'rm -f ...' EXIT TERM` para garantir a limpeza será mantida em cada função.

### 4.5. Verificação de Pré-requisitos

As verificações de ferramentas necessárias (`if ! command -v "$tool"`) serão mantidas em cada função, exibindo uma mensagem clara se uma ferramenta estiver faltando.

### 4.6. Ajuda e Uso (`--help`)

Cada função `ezpz_<comando>` deve ter sua própria mensagem de `usage` detalhada, exibida quando o usuário passa `-h` ou `--help`.

## 5. Processo de Refatoração (Instruções para o Cursor)

A refatoração seguirá um fluxo iterativo, com o Cursor fazendo perguntas para garantir a compreensão e a fidelidade ao design.

### 5.1. Etapa de Seleção da Função (Início)

**EU (Usuário) vou começar o processo com o Cursor, dizendo qual função quero refatorar.**
Exemplo: "Cursor, vamos começar a refatorar a função `loot`."

### 5.2. Etapa de Análise e Perguntas (Pelo Cursor)

Após eu selecionar uma função, o Cursor deverá seguir este roteiro de perguntas para entender completamente a função e seus requisitos antes de escrever qualquer código. **O Cursor deve fazer UMA PERGUNTA POR VEZ e esperar minha resposta.**

**Roteiro de Perguntas do Cursor para CADA FUNÇÃO (se aplicável):**

1.  **Visão Geral e Propósito:**
    *   "Ok, vamos refatorar a função `[NOME_DA_FUNÇÃO]`. Pelo script original (`old/ezpz.sh`), ela tem o objetivo de `[DESCRIÇÃO DO OBJETIVO DA FUNÇÃO]`. Você confirma esse propósito geral?"

2.  **Argumentos Obrigatórios:**
    *   "A função `[NOME_DA_FUNÇÃO]` no Zsh exige os seguintes argumentos obrigatórios: `[LISTA DE ARGUMENTOS OBRIGATÓRIOS, ex: -t TARGET, -u USER]`. Você gostaria de manter esses argumentos como obrigatórios no Fish, ou há alguma mudança na sua natureza (ex: pode vir de um arquivo em vez de um único valor)?"

3.  **Argumentos Opcionais:**
    *   "Além dos obrigatórios, a função `[NOME_DA_FUNÇÃO]` aceita os seguintes argumentos opcionais: `[LISTA DE ARGUMENTOS OPCIONAIS, ex: -p PASSWORD, -H HASH, -k]`. Você deseja manter todos eles? Algum novo argumento opcional deveria ser adicionado, ou algum deve ser removido/modificado (ex: valor padrão)?"

4.  **Lógica de Autenticação (Crucial para funções com autenticação):**
    *   **Se a função exigir autenticação (loot, checkvulns, enumdomain, testcreds, enumuser, enumshares):**
        *   "Esta função parece usar credenciais para interagir com o alvo. Você espera que ela suporte quais tipos de autenticação (usuário/senha, pass-the-hash, Kerberos kcache, anônimo)? E como você quer que a função lide com a inferência de domínio (se o usuário for `DOMAIN\user`, ou se um `-d DOMAIN` for fornecido) para as chamadas `nxc` e `impacket`?"
        *   "Para ferramentas `nxc`, a sintaxe é `nxc <proto> -u user [-p pass | -H hash] [-k] <target>`. Para ferramentas `impacket` (ex: `GetNPUsers.py`), a sintaxe costuma ser `user[:pass] | domain/user[:pass] [-hashes LM:NT] [-k] [-dc-ip IP]`. Confirme se estas são as sintaxes esperadas ou se há alguma nuance específica que a função deve tratar ao construir essas strings."
        *   "Você deseja manter a tentativa de sincronização de tempo com `ntpdate` quando Kerberos é usado, e onde isso deveria ser posicionado no fluxo da função?"
    *   **Se a função NÃO exigir autenticação (netscan, webscan, secretsparse, startresponder):**
        *   "Esta função não parece envolver autenticação direta. Há alguma interação com credenciais (ex: leitura de arquivos de hash) que precise ser considerada, ou ela opera de forma independente?"

5.  **Verificação de Pré-requisitos:**
    *   "Quais ferramentas (`nmap`, `fping`, `nxc`, `whatweb`, `ffuf`, `secretsdump.py`, etc.) são absolutamente essenciais para a execução desta função? Confirme os nomes exatos dos binários esperados no `$PATH`."

6.  **Tratamento de Arquivos/Diretórios Temporários:**
    *   "A função original usa arquivos temporários `[NOMES_DE_ARQUIVOS_TMP]`. Você deseja manter o mesmo padrão de criação (`mktemp`) e limpeza (`trap`) no Fish?"

7.  **Output e Colorização:**
    *   "A função original usa padrões de cor como `\033[1;35m[!] Dumping machine information... \033[0m` e `\033[0;36m[*] Hostname \033[0m`. Como você gostaria que estas mensagens fossem coloridas no Fish usando `set_color`? Você prefere usar funções auxiliares para isso (ex: `ezpz_header "Mensagem"` para cores fixas)?"
    *   "Existe algum output específico (ex: IPs, hashes, vulnerabilidades) que você gostaria de destacar com uma cor diferente (`set_color red`, `set_color green`) ou que o `grep` colorido original deve replicar?"

8.  **Comportamento em Erro/Edge Case:**
    *   "Como a função deve se comportar se um argumento obrigatório estiver faltando, ou se uma ferramenta essencial não for encontrada? Deve exibir a mensagem de `usage` e sair com erro (`return 1`)?"
    *   "Há algum outro 'edge case' específico que esta função precisa lidar (ex: ausência de um arquivo `hosts.txt` para `enumshares` sem `-t`)?"

9.  **Mensagem de Uso (`--help`):**
    *   "Qual a mensagem de `usage` concisa e o texto de ajuda detalhado você gostaria que fossem exibidos quando a função for chamada com `--help` ou `-h`? Pense nos argumentos e nos exemplos de uso."

### 5.3. Etapa de Geração de Código (Pelo Cursor)

Uma vez que o Cursor tenha todas as informações necessárias, ele irá gerar o código para a função `ezpz_<NOME_DA_FUNÇÃO>.fish`, incluindo:

*   A definição da função com `function ... end`.
*   Parsing de argumentos usando `argparse` ou lógica manual (se mais simples).
*   Lógica de autenticação adaptada e construída *internamente*.
*   Chamadas às ferramentas com os argumentos formatados para Fish.
*   Tratamento de arquivos temporários.
*   Colorização de output usando `set_color` ou funções auxiliares.
*   Mensagem de `usage` e ajuda.

O Cursor apresentará o código completo e explicará as principais mudanças em relação ao Zsh.

### 5.4. Etapa de Revisão e Teste (Pelo Usuário)

Após o Cursor gerar o código, eu (o usuário) serei responsável por:

*   Revisar o código gerado para garantir que atenda aos requisitos.
*   Salvar o código no arquivo `ezpz/functions/ezpz_<NOME_DA_FUNÇÃO>.fish`.
*   **Testar a função exaustivamente** no meu ambiente Fish real.
*   Fornecer feedback ao Cursor sobre quaisquer bugs ou ajustes necessários.

## 6. Definições de Cores e Estilos (Para o Cursor)

Para garantir uma saída visual consistente e legível no Fish, o Cursor deve usar as seguintes diretrizes para colorização:

*   **Comando Base:** `set_color <cor> [--bold | --underline]`
*   **Reset:** `set_color normal` (ou `set_color -r`)
*   **Cores Padrão Sugeridas para EZPZ (conforme o original):**
    *   `\033[1;35m[...]`: **Magenta forte (negrito)** para títulos de seções/headers (`set_color magenta --bold`).
        *   Exemplo: `echo (set_color magenta --bold)"[!] Dumping machine information..."(set_color normal)`
    *   `\033[0;36m[*]`: **Ciano** para itens de progresso/scanning (`set_color cyan`).
        *   Exemplo: `echo (set_color cyan)"[*] Hostname"(set_color normal)`
    *   `\033[0;34m[>]`: **Azul** para exibir os comandos sendo executados (`set_color blue`).
        *   Exemplo: `echo (set_color blue)"[>] nmap -sn "$target"..."(set_color normal)`
    *   `\033[1;31m[!]`: **Vermelho forte (negrito)** para erros ou avisos finais (`set_color red --bold`).
        *   Exemplo: `echo (set_color red --bold)"[!] Missing target parameter."(set_color normal)`
    *   `\033[0;33m[*]`: **Amarelo** para avisos/sugestões não-críticos (`set_color yellow`).
        *   Exemplo: `echo (set_color yellow)"[*] DonPAPI suggestion skipped..."(set_color normal)`
    *   `\033[1;36m[?]`: **Ciano forte (negrito)** para perguntas interativas (`set_color cyan --bold`).
        *   Exemplo: `echo (set_color cyan --bold)"[?] Add discovered hosts to /etc/hosts? [y/N] "(set_color normal)`
    *   **Destaques:** Para palavras específicas como "(Pwn3d!)" ou "True" (DBA status), o Cursor pode usar `string replace` ou lógica similar para aplicar cores dinamicamente, mantendo a originalidade do `highlight` e `color` do Zsh.

**Sugestão de funções auxiliares (Cursor pode implementá-las no `ezpz.fish` ou em um arquivo `ezpz_colors.fish` separado):**

```fish
# Funções de ajuda para colorização
function ezpz_header
    echo (set_color magenta --bold)"$argv"(set_color normal)
end

function ezpz_info_star
    echo (set_color cyan)"[*] "$argv(set_color normal)
end

function ezpz_cmd_display
    echo (set_color blue)"[>] "$argv(set_color normal)
end

function ezpz_error
    echo (set_color red --bold)"[!] "$argv(set_color normal)
end

function ezpz_warning
    echo (set_color yellow)"[*] "$argv(set_color normal)
end

function ezpz_question
    echo (set_color cyan --bold)"[?] "$argv(set_color normal)
end

# A função dispatcher pode ter uma função para aplicar destaque em texto específico.
# Isso será implementado quando a função específica for refatorada, conforme a necessidade.
```

## 7. Referências

*   **Script Zsh Original:** `old/ezpz.sh` (para ser consultado pelo Cursor).
*   **Documentação Oficial do Fish Shell:** [https://fishshell.com/docs/current/index.html](https://fishshell.com/docs/current/index.html)
*   **`argparse` no Fish:** [https://fishshell.com/docs/current/cmds/argparse.html](https://fishshell.com/docs/current/cmds/argparse.html)
*   **`set_color` no Fish:** [https://fishshell.com/docs/current/cmds/set_color.html](https://fishshell.com/docs/current/cmds/set_color.html)
