2 SWS, Selbststudium auf Leistungsschein




# Fuzzing - Ein kurzer Überblick
Hauptseminar zum Thema Fuzzing

Fuzzing ist eine Methode aus dem Software- bzw. Hardwaretesting und ist seit den 1980er Jahren bekannt und seitdem immer weiter erforscht und verbessert.
Die Grundidee ist dabei sehr simpel und besteht aus zwei Schritten:
1. ein System mit zufälligen Daten starten
2. einen Systemabsturz und dessen Ursache protokollieren
Diese beiden Schritten werden dann sehr oft ausgeführt (tausend- oder millionenfach).

Durch das simple Prinzip ist eine naive Implementierung sehr einfach und für neue Systeme ohne bestehende Fuzzing-Software lassen sich sehr schnell einfache Fuzzing-Tests schreiben. Da im Gegensatz zu Unit Test bzw. positiven Tests (TODO: Begriff positive Tests checken) nicht die Spezifikation herangenommen wird, werden relativ einfach auch Fehler bei Randfälle und Szenarien ausßerhalb der Spezifikation gefunden. Zusätzlich ist der Wartungsaufwand gering: beim initialen Aufsetzen muss man keine Testfälle spezifieren sondern nur das System. danach werden ohne weiteren manuellen Aufwand die Tests durchlaufen. Auch muss man bei Systemänderungen nicht die Testfallspezifikationen anpassen.
Nachteilig ist die Einschränkung von Fuzzing, dass nur die Robustheit getestet wird, dass heißt ob das Programm abstürzt oder sich aufhängt. Eine Verifikation der Ergebnisse findet nicht statt. Außerdem ist der Rechenaufwand hoch, so muss man bei komplexeren Systemen, die sich nicht isolieren lassen und große Eingabedaten benötigen sehr viele Tests ausführen und entweder tage- bzw. wochenlang fuzzen oder statt einem Rechner dutzende oder hunderte verwenden.


## Techniken
Grundsätzlich lassen sich mehrere Aspekte unterscheiden: zum einen welches System gefuzzt wird und zum anderen wie die Daten generiert werden.
In diesem Zusammenhang kann System für mehrere Sachen stehen: zum einen für Programme, dann Betriebssysteme (als Unterform von Programmen) sowie Hardware. 
Die Datengenerierung kann durch mehrere Methoden geschehen: zufälliges Fuzzing, mutationsbasiertes Fuzzing, regelbasiertes Fuzzing sowie instrumentiertes Fuzzing.
Wie die generierten Daten an das gefuzzte System kommen ist lediglich eine Frage, welche Schnittstellen das System zur Verfügung stellt. Bei  Programmen können dies beispielsweise Dateien,
`stdin` oder Netzwerkschnittstellen (beispielsweise bei Server) sein. Betriebssysteme werden oft über die spezifischen Schnittstellen wie `syscalls` oder `ioctl` angesprochen oder emulierte Hardwaregeräte
wie USB-Geräte senden Daten an das Betriebssystem und dessen Treiber. Hardware kann zum einen über das ändern der elektrischen Signale gefuzzt werden oder bei Prozessoren über die Maschinenbefehle. 
Ich lege den Fokus im Weiteren auf Software und gehe dabei auf ein paar Besonderheiten dabei ein. Die grundsätzlichen Methoden lassen sich dabei aber genauso gut auf Hardwaresysteme übertragen.



### Zufälliges Fuzzing  (random fuzzing)
Bei zufälligen Fuzzing werden, wie schon der Name andeutet, rein zufällige Daten an das System geschickt. Diese Methode ist sehr einfach und simpel zu implementieren (in Linux beispielsweise `cat /dev/urandom |  programm\_to\_fuzz`), aber dafür nicht sehr effizient. So reichen schon einfachste Validierungen der Eingangsdaten, um diese als fehlerhaft zu erkennen. Da das System in diesem Fall die Verarbeitung beendet, werden nur kleine Teile des Programms getestet.

### Mutationsbasiertes Fuzzing (mutation based fuzzing)
Eine deutlich effizientere Testmöglichkeit bietet das mutationsbasierte Fuzzing (engl. mutation-based fuzzing). Dabei wir zuerst eine Sammlung von Testdaten angelegt, Testkorpus genannt. Diese werden dann zufällig verändert (mutiert) und in das Programm gespeist. Diese Methode ist sehr einfach zu implementieren und effizient im Fehler finden. Da noch ein großer Teil der Daten valide ist, im Gegensatz zum zufälligen Fuzzing, werden die Daten angefangen zu verarbeiten. Simple Validierungen und Datenüberprüfungen erkennen die Daten als korrekt an.
Ein Nachteil dieser Methode ist die große Abhängigkeit von der Testdatenauswahl. Für eine möglichst hohe Testabdeckung müssen viele Programmzweige durchlaufen werden. Dies geschieht aber nur, falls die Testdaten geeignet dafür sind und möglichst viele Fälle abdecken. Beispielsweise sollte man um einen PDF-Reader zu testen nicht nur simple PDF-Dateien mit Text verwenden, sondern es sollten auch Bilder, Videos und komplizierte Layouts verwendet werden. 

* Tools: `zzuf`, `Radamsa`
 
### Regelbasiertes Fuzzing (generation based fuzzing)
Eine ähnliche Methode ist das das regelbasierte Fuzzing (engl. generation based fuzzing). Dabei wird auf Grundlage dieser Spezifikation eine Beschreibung der Daten generiert, beispielsweise eine Grammatik oder ein Protokoll, und daraus werden Sequenzen generiert. Diese generierten Sequenzen lassen sich dann wieder zufällig mutieren. Zusätzlich lassen sich aber auch komplette Nachrichten der Kommunikation wiederholen oder weglassen. Dies hat den Vorteil einer einfachen Entdeckung auch komplexer Logik- und Protokollfehler, wenn beispielsweise die interne Zustandsautomat fehlerhafte Übergange hat.
Durch die Notwendigkeit der Beschreibung ist der anfängliche Aufwand sehr hoch, diese Beschreibung muss zuerst erstellt werden. Außerdem müssen überhaupt die Daten wohlgeformt sein und einer Spezifikation genügen. Zusätzlich ist dann der Erfolg des Fuzzing stark abhängig von der Güte der Beschreibung, ob diese alle Aspekte modeliert oder nicht.

* Tools: `Peach Fuzzer`, `Dharma`
  
### Instrumentiertes Fuzzing (coverage guided fuzzing)
Die neuste Entwicklung ist das instrumentierte Fuzzing (engl. coverage guided fuzzing). Dabei wird für alle Eingangsdaten die Codeausführung beobachten und mit diesem Feedback die Eingangsdaten verändert, sodass möglichst viele Codezweige erreicht werden. Wenn beispielsweise durch Mutation eines bestimmten Bytes keinen neuen  Codezweige erreicht werden, wird die Mutation abgebrochen und durch Mutation anderer Bytes versucht, einen neuen Codezweig zu erreichen. Typischerweise ist auch hier Ausgangspunkt ein Korpus an Testdaten, die mutiert werden.
Diese Methode setzt natürlich voraus, dass man die Codeausführung beobachten kann. Wenn der Quellcode verfügbar ist, wird dies meist durch spezielle eingefügte Instruktionen erreicht. Natürlich ist auch die Verwendung eines Debuggers möglich. Der generelle Vorteil ist eine hohe Effizienz, da nur Bytes verändert werden, die einen Einfluss auf den Programmablauf haben. Dadurch wird außderdem eine hohe Code-Abdeckung erreicht. Nachteil ist eine geringere Performance, entweder durch die zusätzlichen Instruktionen oder durch den Debugger. Dieser Performancenachteil darf dabei nicht größer werden als die verbesserte Effizienz, da sonst die Gesamtzahl an gefunden Fehlern im Programm sinkt.
Ein weiterer Vorteil ist die Möglichkeit der Testkorpus- und Testfallminimierung. Bei der Minimierung des Testkorpus werden alle Testdaten zusammengefasst, bei deren Verarbeitung die gleichen Codezweige durchlaufen werden. Die Testfallminimierung verringert die Größe der einzelnen Testdaten, sodass eine möglichst kleiner Datensatz erzeugt wird, bei dessen Verarbeitung trotzdem diesselben Codepfade durchlaufen werden wie beim ursprünglichen, großen Datensatz. Beide Methoden führen zu einer höheren Performance und Effizienz bei den nächsten Fuzzing-Tests.

* Tools: `AFL`, `libFuzzer`, `honggfuzz`
Die Mächtigkeit des instrumentierten Fuzzing zeigt sich an einem Beispiel. Für das Fuzzing einer Bildbibliothek wurde als einziger Testfall eine Textdatei mit dein Inhalt `hello` genommen. Wenn dann das Fuzzing begonnen wird, werden nach und nach die Bytes so verändert, dass neue Codezweige erreicht werden und es nach und nach die Strukturen des Bildformates erhält. Nach einiger Zeit des Fuzzens wird dann sogar ein komplettes valides Bild erzeugt.
[![Erzeugung valider Bilder beim instrumentierten Fuzzing einer Bildbibliothek](https://lh6.googleusercontent.com/proxy/-6MjaR00hYA40HOvCaSW4PF_TvPpqAjNZIwGadsPVaYE9hRrGNTi91BBKlVdXtK4X7E5qf9hgk6kHMrxWaE-WaCckCsgZzA=s0-d "Erzeugung valider Bilder beim instrumentierten Fuzzing einer Bildbibliothek")](https://lcamtuf.blogspot.com/2014/11/pulling-jpegs-out-of-thin-air.html)



### Datenmutation
Das vollständige Verändern aller Bytes mit allen Möglichkeiten ist nicht machbar. So gibt es bei einem 32-Bit Wert 2^32 Möglichkeiten, was viele Tage dauern würde zu fuzzen. Aus diesem Grund muss man den Suchraum einschränken. So werden die Bits nur geflippt oder geshifftet und bei Zahlen Werte dazu addiert und subtrahiert. Außerdem kann man die Zahlen und Zeichenketten durch interesante Werte ersetzen, beispielsweise 0, 1, -1, die maximale und minimale Zahl des Zahlenbereichs, bei Gleitkommazahlen die speziellen Werte `NaN` oder `-Inf` und um Speicherfehler zu erkennen typische Buffergrößen wie 16, 32 oder 128. Interessante Zeichenketten sind beispielsweise komplett leere oder sehr lange Zeichenketten (`''`, `128*'a'`), spezielle Bytes und Zeichen wie `\0` als Ende von Zeichenketten in C oder `\n` als Zeilenumbruch oder Formatierungsbefehle wie `s\%s\%s\%s` oder `\%x \%x \%x` für die Funktion `printf`, die Format String-Angriffe ermöglichen.




Demonstration zufälliger Bit-Flips und Byte-Ersetzungen mittel `zzuf`:

![](https://github.com/ketograph/fuzzing-vortrag/blob/master/images/zzuf1.png "Unveränderter Text")

![](https://github.com/ketograph/fuzzing-vortrag/blob/master/images/zzuf2.png "Manipulierter Text")
    
Datenmanipulation mittels `radamsa`

![](https://github.com/ketograph/fuzzing-vortrag/blob/master/images/radamsa.png "Manipulierter Text")



### Sanitizer
Bestimmte Fehler in Programmen führen nicht oder nicht sofort zu einem Absturz. So kann ein Speicherfehler durch eine fehlerhaften Schreibvorgang erst nach vielen anderen Befehlen zu einem Absturz führen. Oder es wird nur ein sehr kleiner Teil des Speichers beschädigt, sodass nur unter sehr speziellen Umständen das Programm abstürzt. 
Eine Lösung für dieses Problem ist die Verwendung eines Sanitizers. Dieser fügt beim Kompilieren zusätzliche Instruktionen ein, um die Befehle zur Laufzeit zu prüfen. Beispielsweise kann vor jedem Speicherzugriff eine Überprüfung erfolgen, ob tatsächlich auf diesen Speicher zugegriffen werden darf. Ein Nachteil ist die verringerte Performance und der erhöhte Speicherbedarf, die sich beide um den Faktor zwei oder noch stärker verschlechtern können. Da aber beim Fuzzing deutlich mehr Fehler gefunden werden können, ist es trotzdem sinnvoll Sanitizer zu verwenden.
Es wurden verschiedene Sanitizer entwickelt, diese sind aber teilweise nicht für alle Kompiler verfügbar. In der folgenden Tabelle ist eine Übersicht über die verschiedenen Sanitizer, deren erkannten Fehlerklassen und welche Kompiler diese unterstützen. 

| Sanitizer   | Fehlerklassen | Kompiler |
| ----- | --------- | ---- | --- |
| AddressSanitizer (ASan) | Out-of-bounds accesses, Use-after-free, Use-after-return, Use-after-scope, Double-free, invalid free | gcc, clang |
| UndefinedBehaviorSanitizer (UBSan)| (divide by zero, integer overflow),    Using misaligned or null pointer,    Signed integer overflow,    Conversion to, from, or between floating-point types which would overflow the destination | gcc, clang |
| MemorySanitizer | Lesen von uninitialisiertem Speicher | clang |
| LeakSanitizer | Memory leaks | gcc, clang |
| ThreadSanitizer (TSan) | Data races| gcc, clang |
    
  
#### Demonstration Address Sanitizers:
Um die Funktion von Address Sanitizern zu zeigen, ist hier folgendes Beispielprogramm gegeben. Es liest eine Zeichenkette aus `stdin` und kopiert diese in einen 16 Byte großen Buffer. Da keine Überprüfung der Länge der Eingabe erfolgt, werden auch Zeichenketten länger als 16 Bytes in den Buffer kopiert, sodass es zu einem Buffer Overflow kommt. 

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
void func(char **argv) {
  printf("running strcpy...\n");
  char arr[16];
  strcpy(arr, argv[1]);
}
int main(int argc, char *argv[]) {
  if(argc == 2) {
    func(argv);
  }
  return(0);
}
```

Wenn dieses Programm kompiliert und ausgeführt wird, kommt es bei einem Buffer Overflow nicht sofort zum Absturz. Beim Kopieren der Eingabedaten werden einfach die Daten überschrieben. Erst bei einer deutliche längeren Zeichenkette kommt es zu einer Beschädigung des Speichers sodass das Programm abstürzt.

```console
>gcc -o buffer_overflow buffer_overflow.c
>./buffer_overflow aaaaaaaaaaaaaaa # 15*a
running strcpy...
>./buffer_overflow aaaaaaaaaaaaaaaa # 16*a, buffer overflowing
running strcpy...
>./buffer_overflow aaaaaaaaaaaaaaaaaaaaaaaaa # 25*a, buffer overflowing
running strcpy...
*** stack smashing detected ***: <unknown> terminated
```

Sobald aber das Programm mit dem Address Sanitizer kompiliert wird, wird sofort bei einem Überschreiten der zulässigen Zeichenlänge ein Fehler ausgegeben und die Programmausführung stoppt.

```console
>gcc -o buffer_overflow -fsanitize=address buffer_overflow.c
>./buffer_overflow aaaaaaaaaaaaaaa # 15*a
running strcpy...
>./buffer_overflow aaaaaaaaaaaaaaaa # 16*a, buffer overflowing
running strcpy...
=================================================================
==24698==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7fff58d871a0 at pc 0x7face647d741 bp 0x7fff58d87150 sp 0x7fff58d868f8
```


### Tipps und Ratschläge
In der Praxis muss immerzwischen Fuzzing-Geschwindigkeit und Effizienz abgewogen werden. 
* Abwägung Fuzzing-Geschwindigkeit gegenüber Fuzzing-Effizienz: Anzahl gefunder Fehler = Programmausführungen * Sucheffizienz
* Immer Verwendung von Sanitizern
* Teilweise Codeanpassungen nötig: beispielsweise Deaktivierung von Checksummen oder kryptografischen Signaturen



## Tools
### AFL und libFuzzer
Die beiden bekanntesten Fuzzing-Tools sind aktuell der von Michal Zalewski entwickelte Fuzzer american fuzzy lob, kurz afl, sowie der von der LLVM-Community gepflegte libFuzzer. Beide erreichen durch das instrumentieren des Codes eine hohe Effizienz und hohe Code-Abdeckung. Mit beiden wurden hunderte Fehler gefunden und die Heartbleed getaufte Lücke in der OpenSSL-Bibliothek hätte durch Fuzzing in Verbindung mit Sanitizern gefunden werden können.
  
| AFL   | libFuzzer |
| ----- | --------- |
| Sehr schnelles Aufsetzen (5 Minuten) | Schnelles Aufsetzen (½ Stunde) | 
| Übergabe der Daten per `stdin` oder Datei | Übergabe der Daten durch Helferprogramm |
| Gray- und White-Box-Fuzzing | Ausschließlich White-Box-Fuzzing, Kompilierung mit `clang` notwendig |
| Standard: Start vieler Prozesse, Möglichkeit des In-Prozess-Fuzzings| schnell durch In-Prozess-Fuzzing |

#### Quickstart
* AFL
  * Kompilierung:  `CC=afl-gcc ./configure --disable-shared`
  * Ausführung: `afl-fuzz [...] ./programm\_to\_fuzz`
* libFuzzer
  * Implementierung des Helferprogramms: [![](https://github.com/ketograph/fuzzing-vortrag/blob/master/images/libfuzzer_quickstart.png "Fuzzing Ziel erstellen")](http://llvm.org/docs/LibFuzzer.html#id22)
  * Kompilierung: `clang -fsanitize=fuzzer fuzz\_target.c`
  * Ausführung: `./a.out [...]`
  
### Kernel Fuzzer
* `syzkaller`
  * Entwicklung durch Google
  * Instrumentiertes Fuzzing
  * Start des Systems in VM und Fuzzing der Syscalls
* Alternative: `trinity` 
  
### Weitere Tools
* `Sandsifter`
  * Fuzzing von CPU-Instruktionen
  * Entdeckung von Bugs in Disassemblern, Emulatoren, Hypervisorn sowie x86-Chips 
* `ClusterFuzz` und OSS-Fuzz-Projekt
  * Google-Entwicklung zum Fuzzing von Chrome
  * Verteiltes Fuzzing auf hunderten Kernen
  * OSS-Fuzz: Fuzzing verbreiteter  Open-Source-Software


