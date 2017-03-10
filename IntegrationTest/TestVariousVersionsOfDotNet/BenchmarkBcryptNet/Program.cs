using System;
using System.Collections;
using System.Diagnostics;
using System.Reflection;

/// <summary>
///     The attribute to use to mark methods as being
///     the targets of benchmarking.
/// </summary>
[AttributeUsage(AttributeTargets.Method)]
public class BenchmarkAttribute : Attribute
{
}

/// <summary>
///     Very simple benchmarking framework. Looks for all types
///     in the current assembly which have static parameterless
///     methods
/// </summary>
public class Benchmark
{
    public static void Main(string[] args)
    {
        // Save all the benchmark classes from doing a nullity test
        if (args == null)
            args = new string[0];

        // We're only ever interested in public static methods. This variable
        // just makes it easier to read the code...
        var publicStatic = BindingFlags.Public | BindingFlags.Static;

        foreach (var type in Assembly.GetCallingAssembly().GetTypes())
        {
            // Find an Init method taking string[], if any
            var initMethod = type.GetMethod("Init", publicStatic, null,
                new[] { typeof(string[]) },
                null);

            // Find a parameterless Reset method, if any
            var resetMethod = type.GetMethod("Reset", publicStatic,
                null, new Type[0],
                null);

            // Find a parameterless Check method, if any
            var checkMethod = type.GetMethod("Check", publicStatic,
                null, new Type[0],
                null);

            // Find all parameterless methods with the [Benchmark] attribute
            var benchmarkMethods = new ArrayList();
            foreach (var method in type.GetMethods(publicStatic))
            {
                var parameters = method.GetParameters();
                if ((parameters != null) && (parameters.Length != 0))
                    continue;

                if (method.GetCustomAttributes
                        (typeof(BenchmarkAttribute), false).Length != 0)
                    benchmarkMethods.Add(method);
            }

            // Ignore types with no appropriate methods to benchmark
            if (benchmarkMethods.Count == 0)
                continue;

            Console.WriteLine("Benchmarking type {0}", type.Name);

            // If we've got an Init method, call it once
            try
            {
                if (initMethod != null)
                    initMethod.Invoke(null, new object[] { args });
            }
            catch (TargetInvocationException e)
            {
                var inner = e.InnerException;
                var message = inner == null ? null : inner.Message;
                if (message == null)
                    message = "(No message)";
                Console.WriteLine("Init failed ({0})", message);
                continue; // Next type
            }

            foreach (MethodInfo method in benchmarkMethods)
                try
                {
                    // Reset (if appropriate)
                    if (resetMethod != null)
                        resetMethod.Invoke(null, null);

                    // Give the test as good a chance as possible
                    // of avoiding garbage collection
                    GC.Collect();
                    GC.WaitForPendingFinalizers();
                    GC.Collect();

                    // Now run the test itself
                    var start = DateTime.Now;
                    method.Invoke(null, null);
                    var end = DateTime.Now;

                    // Check the results (if appropriate)
                    // Note that this doesn't affect the timing
                    if (checkMethod != null)
                        checkMethod.Invoke(null, null);

                    // If everything's worked, report the time taken,
                    // nicely lined up (assuming no very long method names!)
                    Console.WriteLine("  {0,-20} {1}", method.Name, end - start);
                }
                catch (TargetInvocationException e)
                {
                    var inner = e.InnerException;
                    var message = inner?.Message ?? "(No message)";
                    Console.WriteLine("  {0}: Failed ({1})", method.Name, message);
                }
        }
        Console.ReadLine();
    }

    public class TestBcryptNetv2
    {

        private static string[] pass =
            {
                "123456",
                "password",
                "12345678",
                "1234",
                "pussy",
                "12345",
                "dragon",
                "qwerty",
                "696969",
                "mustang",
                "letmein",
                "baseball",
                "master",
                "michael",
                "football",
                "shadow",
                "monkey",
                "abc123",
                "pass",
                "fuckme",
                "6969",
                "jordan",
                "harley",
                "ranger",
                "iwantu",
                "jennifer",
                "hunter",
                "fuck",
                "2000",
                "test",
                "batman",
                "trustno1",
                "thomas",
                "tigger",
                "robert",
                "access",
                "love",
                "buster",
                "1234567",
                "soccer",
                "hockey",
                "killer",
                "george",
                "sexy",
                "andrew",
                "charlie",
                "superman",
                "asshole",
                "fuckyou",
                "dallas",
                "jessica",
                "panties",
                "pepper",
                "1111",
                "austin",
                "william",
                "daniel",
                "golfer",
                "summer",
                "heather",
                "hammer",
                "yankees",
                "joshua",
                "maggie",
                "biteme",
                "enter",
                "ashley",
                "thunder",
                "cowboy",
                "silver",
                "richard",
                "fucker",
                "orange",
                "merlin",
                "michelle",
                "corvette",
                "bigdog",
                "cheese",
                "matthew",
                "121212",
                "patrick",
                "martin",
                "freedom",
                "ginger",
                "blowjob",
                "nicole",
                "sparky",
                "yellow",
                "camaro",
                "secret",
                "dick",
                "falcon",
                "taylor",
                "111111",
                "131313",
                "123123",
                "bitch",
                "hello",
                "scooter",
                "please",
                "porsche",
                "guitar",
                "chelsea",
                "black",
                "diamond",
                "nascar",
                "jackson",
                "cameron",
                "654321",
                "computer",
                "amanda",
                "wizard",
                "xxxxxxxx",
                "money",
                "phoenix",
                "mickey",
                "bailey",
                "knight",
                "iceman",
                "tigers",
                "purple",
                "andrea",
                "horny",
                "dakota",
                "aaaaaa",
                "player",
                "sunshine",
                "morgan",
                "starwars",
                "boomer",
                "cowboys",
                "edward",
                "charles",
                "girls",
                "booboo",
                "coffee",
                "xxxxxx",
                "bulldog",
                "ncc1701",
                "rabbit",
                "peanut",
                "john",
                "johnny",
                "gandalf",
                "spanky",
                "winter",
                "brandy",
                "compaq",
                "carlos",
                "tennis",
                "james",
                "mike",
                "brandon",
                "fender",
                "anthony",
                "blowme",
                "ferrari",
                "cookie",
                "chicken",
                "maverick",
                "chicago",
                "joseph",
                "diablo",
                "sexsex",
                "hardcore",
                "666666",
                "willie",
                "welcome",
                "chris",
                "panther",
                "yamaha",
                "justin",
                "banana",
                "driver",
                "marine",
                "angels",
                "fishing",
                "david",
                "maddog",
                "hooters",
                "wilson",
                "butthead",
                "dennis",
                "fucking",
                "captain",
                "bigdick",
                "chester",
                "smokey",
                "xavier",
                "steven",
                "viking",
                "snoopy",
                "blue",
                "eagles",
                "winner",
                "samantha",
                "house",
                "miller",
                "flower",
                "jack",
                "firebird",
                "butter",
                "united",
                "turtle",
                "steelers",
                "tiffany",
                "zxcvbn",
                "tomcat",
                "golf",
                "bond007",
                "bear",
                "tiger",
                "doctor",
                "gateway",
                "gators",
                "angel",
                "junior",
                "thx1138",
                "porno",
                "badboy",
                "debbie",
                "spider",
                "melissa",
                "booger",
                "1212",
                "flyers",
                "fish",
                "porn",
                "matrix",
                "teens",
                "scooby",
                "jason",
                "walter",
                "cumshot",
                "boston",
                "braves",
                "yankee",
                "lover",
                "barney",
                "victor",
                "tucker",
                "princess",
                "mercedes",
                "5150",
                "doggie",
                "zzzzzz",
                "gunner",
                "horney",
                "bubba",
                "2112",
                "fred",
                "johnson",
                "xxxxx",
                "tits",
                "member",
                "boobs",
                "donald",
                "bigdaddy",
                "bronco",
                "penis",
                "voyager",
                "rangers",
                "birdie",
                "trouble",
                "white",
                "topgun",
                "bigtits",
                "bitches",
                "green",
                "super",
                "qazwsx",
                "magic",
                "lakers",
                "rachel",
                "slayer",
                "scott",
                "2222",
                "asdf",
                "video",
                "london",
                "7777",
                "marlboro",
                "srinivas",
                "internet",
                "action",
                "carter",
                "jasper",
                "monster",
                "teresa",
                "jeremy",
                "11111111",
                "bill",
                "crystal",
                "peter",
                "pussies",
                "cock",
                "beer",
                "rocket",
                "theman",
                "oliver",
                "prince",
                "beach",
                "amateur",
                "7777777",
                "muffin",
                "redsox",
                "star",
                "testing",
                "shannon",
                "murphy",
                "frank",
                "hannah",
                "dave",
                "eagle1",
                "11111",
                "mother",
                "nathan",
                "raiders",
                "steve",
                "forever",
                "angela",
                "viper",
                "ou812",
                "jake",
                "lovers",
                "suckit",
                "gregory",
                "buddy",
                "whatever",
                "young",
                "nicholas",
                "lucky",
                "helpme",
                "jackie",
                "monica",
                "midnight",
                "college",
                "baby",
                "cunt",
                "brian",
                "mark",
                "startrek",
                "sierra",
                "leather",
                "232323",
                "4444",
                "beavis",
                "bigcock",
                "happy",
                "sophie",
                "ladies",
                "naughty",
                "giants",
                "booty",
                "blonde",
                "fucked",
                "golden",
                "0",
                "fire",
                "sandra",
                "pookie",
                "packers",
                "einstein",
                "dolphins",
                "chevy",
                "winston",
                "warrior",
                "sammy",
                "slut",
                "8675309",
                "zxcvbnm",
                "nipples",
                "power",
                "victoria",
                "asdfgh",
                "vagina",
                "toyota",
                "travis",
                "hotdog",
                "paris",
                "rock",
                "xxxx",
                "extreme",
                "redskins",
                "erotic",
                "dirty",
                "ford",
                "freddy",
                "arsenal",
                "access14",
                "wolf",
                "nipple",
                "iloveyou",
                "alex",
                "florida",
                "eric",
                "legend",
                "movie",
                "success",
                "rosebud",
                "jaguar",
                "great",
                "cool",
                "cooper",
                "1313",
                "scorpio",
                "mountain",
                "madison",
                "987654",
                "brazil",
                "lauren",
                "japan",
                "naked",
                "squirt",
                "stars",
                "apple",
                "alexis",
                "aaaa",
                "bonnie",
                "peaches",
                "jasmine",
                "kevin",
                "matt",
                "qwertyui",
                "danielle",
                "beaver",
                "4321",
                "4128",
                "runner",
                "swimming",
                "dolphin",
                "gordon",
                "casper",
                "stupid",
                "shit",
                "saturn",
                "gemini",
                "apples",
                "august",
                "3333",
                "canada",
                "blazer",
                "cumming",
                "hunting",
                "kitty",
                "rainbow",
                "112233",
                "arthur",
                "cream",
                "calvin",
                "shaved",
                "surfer",
                "samson",
                "kelly",
                "paul",
                "mine",
                "king",
                "racing",
                "5555",
                "eagle",
                "hentai",
                "newyork",
                "little",
                "redwings",
                "smith",
                "sticky",
                "cocacola",
                "animal",
                "broncos",
                "private",
                "skippy",
                "marvin",
                "blondes",
                "enjoy",
                "girl",
                "apollo",
                "parker",
                "qwert",
                "time",
                "sydney",
                "women",
                "voodoo",
                "magnum",
                "juice",
                "abgrtyu",
                "777777",
                "dreams",
                "maxwell",
                "music",
                "rush2112",
                "russia",
                "scorpion",
                "rebecca",
                "tester",
                "mistress",
                "phantom",
                "billy",
                "6666",
                "albert"
            };

        static int iterations = 1;

        [Benchmark]
        public static void Test()
        {
            int count = iterations;
            for (int i = 0; i < count; i++)
                foreach (var p in pass)
                {
                    var x = BCrypt.Net.BCrypt.HashPassword(p, 10);
                    Debug.Assert(BCrypt.Net.BCrypt.Verify(p, x));
                }
        }
    }
}