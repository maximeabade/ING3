# AUTOPENBENCH: Benchmarking Generative Agents for Penetration Testing

## Sommaire
- [AUTOPENBENCH: Benchmarking Generative Agents for Penetration Testing](#autopenbench-benchmarking-generative-agents-for-penetration-testing)
  - [Sommaire](#sommaire)
  - [1. Introduction](#1-introduction)
  - [2. Benchmark Overview](#2-benchmark-overview)
  - [3. Generative Agents](#3-generative-agents)
  - [4. Experimental Results](#4-experimental-results)
  - [5. Additional Analysis](#5-additional-analysis)
  - [6. Conclusion](#6-conclusion)

## 1. Introduction
La première partie de l'article aborde les défis des tests de pénétration (pentesting), un domaine complexe de la cybersécurité qui consiste à réaliser des cyberattaques simulées pour tester les systèmes de sécurité d'une organisation. Face à la difficulté et à la complexité de ces tests, des solutions automatisées, y compris des outils classiques comme Metasploit, sont de plus en plus explorées. Récemment, des agents génératifs basés sur des modèles de langage (LLM) ont émergé comme une approche prometteuse pour automatiser certains aspects des tests de pénétration. Cependant, il manque encore un cadre standardisé pour évaluer et comparer ces agents de manière uniforme. L’article introduit **AUTOPENBENCH**, un banc d'essai ouvert visant à combler cette lacune. Ce cadre propose 33 tâches organisées selon plusieurs niveaux de difficulté, permettant ainsi de tester les capacités des agents dans divers scénarios, du simple au réel.

## 2. Benchmark Overview
Dans cette section, les auteurs décrivent l'infrastructure du banc d'essai AUTOPENBENCH. Il s'agit de tâches de pentesting impliquant des systèmes vulnérables hébergés dans des conteneurs Docker. Les tâches sont divisées en deux catégories principales :

- **In-vitro tasks** : des scénarios de pentesting plus simples, souvent rencontrés dans les cours de cybersécurité (22 tâches au total).
- **Real-world tasks** : des scénarios plus complexes basés sur des failles de sécurité réelles (11 tâches au total).

Chaque tâche est mesurée à travers des "jalons" ou **milestones**, à la fois des commandes spécifiques que l'agent doit exécuter et des phases générales de l'attaque (découverte, infiltration, exploitation, etc.). Ce système de jalons permet d’évaluer objectivement les progrès de l’agent à chaque étape de la tâche.

## 3. Generative Agents
Cette section présente deux types d'architectures d'agents basées sur le framework **CoALA**. 

- **Autonomous agent** : L’agent autonome exécute une série de procédures de raisonnement et d'actions basées sur les instructions fournies et les observations de l’environnement. Il utilise une approche "ReACT" pour gérer les actions et pensées séparément afin d'améliorer la cohérence des actions.
- **Assisted agent** : Cet agent permet la collaboration avec un utilisateur humain, divisant la tâche globale en sous-tâches plus petites, chaque sous-tâche étant attribuée par l’utilisateur. Cela permet à l’agent de se concentrer sur des étapes spécifiques sans être distrait par une tâche trop complexe.

## 4. Experimental Results
Les résultats expérimentaux montrent les performances des deux agents sur les 33 tâches du banc d'essai.

- **Agent autonome** : Cet agent parvient à résoudre 21 % des tâches dans l’ensemble. Il réussit mieux dans les tâches simples (27 % de taux de réussite pour les tâches in-vitro) mais échoue dans les scénarios réels, avec un taux de réussite très faible (9 %).
- **Agent assisté** : L’agent semi-autonome montre des améliorations significatives avec un taux de réussite global de 64 %, notamment grâce à la collaboration avec un utilisateur humain. Il réussit 73 % des tâches du monde réel, indiquant l’importance de l’interaction homme-machine dans ces tests.

## 5. Additional Analysis
Dans cette partie, les auteurs réalisent des tests supplémentaires pour comparer l'efficacité des différents **LLM** utilisés par les agents et étudier leur cohérence dans l’exécution des tâches. Ils testent plusieurs modèles de LLM (par exemple, GPT-4, GPT-4 turbo, OpenAI o1) sur certaines tâches. Les résultats montrent que certains modèles, comme **GPT-4o**, sont plus adaptés aux tâches de pentesting grâce à une meilleure gestion des commandes structurées et des sorties formatées.

## 6. Conclusion
L'article conclut que même si les agents génératifs autonomes ont encore des limites dans les scénarios complexes de tests de pénétration, ils montrent des promesses. L'agent assisté, en particulier, démontre comment la collaboration homme-machine peut améliorer l’efficacité des tests. **AUTOPENBENCH** constitue un cadre flexible pour évaluer et comparer les agents sur des tâches de cybersécurité, et les auteurs espèrent que la communauté élargira ce cadre en ajoutant de nouveaux scénarios et de nouvelles tâches.

En résumé, **AUTOPENBENCH** comble un vide en proposant un banc d'essai ouvert pour l'évaluation des agents de tests de pénétration automatisés, avec l’objectif d’améliorer et standardiser leur développement et leur comparaison.
