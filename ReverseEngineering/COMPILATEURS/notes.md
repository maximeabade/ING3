# COMPILATEUR

## Etapes de compilation
- Parsing
- Préprocessing
- Compilation
- Assemblage (instructions assembleur + stockage dans un objet)

main.c -> préprocessing *gcc -E* -> main.i *code étendu*-> compilation *gcc -S*-> main.s *code asm*-> assemblage *us, gcc -c*-> main.o *objet*-> linkage *ld , gcc*-> binaire ELF *./a.out*


## Graphes de compilation - GCC's CFG (Control Flow Graph)
```gcc -fdump-tree-all-graph helloworld.c -o helloworld.o ``` <br>
```gcc -fdump-ipa-all-graph helloworld.c -o helloworld.o  ``` <br>
``` gcc -fdump-rtl-all-graph helloworld.c -o helloworld.o ``` <br>
**Visualisation** : ```dot -Tpng helloworld.o-helloworld.c.017t.ompexp.dot -o helloworld.png```