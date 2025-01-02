---
uid: salts
---

# Salts in bCrypt

This implementation on hashing will generate a salt automatically for you with the work factor (2^number of rounds) set to 11 (which matches the default across most implementation and is currently viewed as a good level of security/risk).

To save you the maths a small table covering the iterations is provided below. The minimum allowed in this library is 4 for compatibility, the maximum is 31 (at 31 your processor will be wishing for death).

```text
| Cost  | Iterations               |
|-------|--------------------------|
|   8   |    256 iterations        |
|   9   |    512 iterations        |
|  10   |  1,024 iterations        |
|  11   |  2,048 iterations        |
|  12   |  4,096 iterations        |
|  13   |  8,192 iterations        |
|  14   | 16,384 iterations        |
|  15   | 32,768 iterations        |
|  16   | 65,536 iterations        |
|  17   | 131,072 iterations       |
|  18   | 262,144 iterations       |
|  19   | 524,288 iterations       |
|  20   | 1,048,576 iterations     |
|  21   | 2,097,152 iterations     |
|  22   | 4,194,304 iterations     |
|  23   | 8,388,608 iterations     |
|  24   | 16,777,216 iterations    |
|  25   | 33,554,432 iterations    |
|  26   | 67,108,864 iterations    |
|  27   | 134,217,728 iterations   |
|  28   | 268,435,456 iterations   |
|  29   | 536,870,912 iterations   |
|  30   | 1,073,741,824 iterations |
|  31   | 2,147,483,648 iterations |

etc
```

and a simple benchmark you can run by creating a console program, adding this BCrypt Library and using this code.

```csharp
    var cost = 16;
    var timeTarget = 100; // Milliseconds
    long timeTaken;
    do
    {
        var sw = Stopwatch.StartNew();

        BCrypt.HashPassword("RwiKnN>9xg3*C)1AZl.)y8f_:GCz,vt3T]PI", workFactor: cost);

        sw.Stop();
        timeTaken = sw.ElapsedMilliseconds;

        cost -= 1;

    } while ((timeTaken) >= timeTarget);

    Console.WriteLine("Appropriate Cost Found: " + (cost + 1));
    Console.ReadLine();
```

This will start at 16 which is `65,536 iterations` and reduce the cost until the time target is reached.
It's up to you what you consider an allowable time, but if it’s below 10, I’d seriously advise leaving it at 10
and maybe investing in a larger server package.
