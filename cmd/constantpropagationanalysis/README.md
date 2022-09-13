# Constant Propagation Analysis
Use the main.go to have a try\
Below is the output of main.go\
The first part is the SSA format of the source code and the second part is the constant propagation on SSA
```
# Name: constantpropagtionanalysis.Hello
# Package: constantpropagtionanalysis
# Location: 3:6
func Hello(a int, b int) bool:
0:                                                                entry P:0 S:2
        t0 = 1:int + 3:int                                                  int
        t1 = b + 2:int                                                      int
        t2 = t0 > t1                                                       bool
        if t2 goto 1 else 3
1:                                                              if.then P:1 S:1
        t3 = t0 + 1:int                                                     int
        jump 2
2:                                                              if.done P:2 S:0
        t4 = phi [1: t3, 3: t6] #x                                          int
        t5 = t4 > 0:int                                                    bool
        return t5
3:                                                              if.else P:1 S:1
        t6 = t1 + 1:int                                                     int
        jump 2

constant fact for instruction: 1:int + 3:int
a=UNDEF b=UNDEF t0=4 

constant fact for instruction: b + 2:int
a=UNDEF b=UNDEF t0=4 t1=UNDEF 

constant fact for instruction: t0 > t1
a=UNDEF b=UNDEF t0=4 t1=UNDEF t2=UNDEF 

constant fact for instruction: if t2 goto 1 else 3
a=UNDEF b=UNDEF t0=4 t1=UNDEF t2=UNDEF 

constant fact for instruction: t1 + 1:int
a=UNDEF b=UNDEF t0=4 t1=UNDEF t2=UNDEF t6=UNDEF 

constant fact for instruction: jump 2
a=UNDEF b=UNDEF t0=4 t1=UNDEF t2=UNDEF t6=UNDEF 

constant fact for instruction: t0 + 1:int
a=UNDEF b=UNDEF t0=4 t1=UNDEF t2=UNDEF t3=5 

constant fact for instruction: jump 2
a=UNDEF b=UNDEF t0=4 t1=UNDEF t2=UNDEF t3=5 

constant fact for instruction: phi [1: t3, 3: t6] #x
a=UNDEF b=UNDEF t0=4 t1=UNDEF t2=UNDEF t3=5 t4=5 t6=UNDEF 

constant fact for instruction: t4 > 0:int
a=UNDEF b=UNDEF t0=4 t1=UNDEF t2=UNDEF t3=5 t4=5 t5=NAC t6=UNDEF 

constant fact for instruction: return t5
a=UNDEF b=UNDEF t0=4 t1=UNDEF t2=UNDEF t3=5 t4=5 t5=NAC t6=UNDEF 
```