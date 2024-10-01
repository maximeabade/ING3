# COMPILATEUR

## Etapes de compilation
- Parsing
- Préprocessing
- Compilation
- Assemblage (instructions assembleur + stockage dans un objet)

main.c -> préprocessing *gcc -E* -> main.i *code étendu*-> compilation *gcc -S*-> main.s *code asm*-> assemblage *us, gcc -c*-> main.o *objet*-> linkage *ld , gcc*-> binaire ELF *./a.out*


## Graphes de compilation
```gcc -fdump-tree-all-graph helloworld.c -o helloworld.o``` 
```gcc -fdump-ipa-all-graph helloworld.c -o helloworld.o``` 
```gcc -fdump-rtl-all-graph helloworld.c -o helloworld.o``` 

