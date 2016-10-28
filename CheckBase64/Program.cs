using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CheckBase64
{
    public class Program
    {
        public static void Main(string[] args)
        {
            string sIdtoken = "eyJhbGciOiJSUzI1NiJ9.eyJodHRwOlwvXC93c28yLm9yZ1wvY2xhaW1zXC9pZGVudGl0eVwvdW5sb2NrVGltZSI6IjAiLCJzdWIiOiJhbmRyZWFzX2xhbmdAdHJpbWJsZS5jb20iLCJodHRwOlwvXC93c28yLm9yZ1wvY2xhaW1zXC9hY2NvdW50bmFtZSI6InRyaW1ibGUuY29tIiwiYXpwIjoiSEE3NG02UFBZN1NzX19zejBVTVVER2ltTVlZYSIsImh0dHA6XC9cL3dzbzIub3JnXC9jbGFpbXNcL2ZpcnN0bmFtZSI6IkFuZHJlYXMiLCJhdF9oYXNoIjoibDBJQ21MNjRORndRY2FNNVVYb2R3dyIsImlzcyI6Imh0dHBzOlwvXC9pZGVudGl0eS1zdGcudHJpbWJsZS5jb20iLCJodHRwOlwvXC93c28yLm9yZ1wvY2xhaW1zXC9sYXN0bmFtZSI6IkxhbmciLCJodHRwOlwvXC93c28yLm9yZ1wvY2xhaW1zXC90ZWxlcGhvbmUiOiIrNDk4OTg5MDU3MTQ4NCIsImh0dHA6XC9cL3dzbzIub3JnXC9jbGFpbXNcL3V1aWQiOiI2YmM5YTllMS1hNTI3LTQ0NWMtYWNlNS1lZTEyMTZkNmRjMjgiLCJpYXQiOjE0Nzc1Nzg3NzcsImh0dHA6XC9cL3dzbzIub3JnXC9jbGFpbXNcL2dpdmVubmFtZSI6IkFuZHJlYXMiLCJhdXRoX3RpbWUiOjE0Nzc1NzQ1MDAsImV4cCI6MTQ3NzU4MjM3NywiaHR0cDpcL1wvd3NvMi5vcmdcL2NsYWltc1wvaWRlbnRpdHlcL2ZhaWxlZExvZ2luQXR0ZW1wdHMiOiIwIiwiaHR0cDpcL1wvd3NvMi5vcmdcL2NsYWltc1wvaWRlbnRpdHlcL2FjY291bnRMb2NrZWQiOiJmYWxzZSIsImh0dHA6XC9cL3dzbzIub3JnXC9jbGFpbXNcL2NvdW50cnkiOiJHZXJtYW55IiwiYXVkIjpbIkhBNzRtNlBQWTdTc19fc3owVU1VREdpbU1ZWWEiXSwiaHR0cDpcL1wvd3NvMi5vcmdcL2NsYWltc1wvZW1haWxhZGRyZXNzIjoiYW5kcmVhc19sYW5nQHRyaW1ibGUuY29tIiwiaHR0cDpcL1wvd3NvMi5vcmdcL2NsYWltc1wvYWNjb3VudHVzZXJuYW1lIjoiYW5kcmVhc19sYW5nIn0.pI82";

            var sentences = new List<String>();
            int position = 0;
            int start = 0;
            // Extract sentences from the string.
            do
            {
                position = sIdtoken.IndexOf('.', start);
                if (position >= 0)
                {
                    sentences.Add(sIdtoken.Substring(start, position - start).Trim());
                    start = position + 1;
                }
            } while (position > 0);

            // Display the sentences.
            foreach (var sentence in sentences)
            {
                string str = sentence;
                Console.WriteLine("Decode: '" + str + "'");
                while (str.Length %4 != 0)
                {
                    str += "=";
                }
                byte[] xconvbytes = Convert.FromBase64String(str);
                StringBuilder sb = new StringBuilder();

                sb.Append(System.Text.UTF8Encoding.UTF8.GetChars(xconvbytes));

                string sTmpDecoded = sb.ToString();
                Console.WriteLine("    to: '" + sTmpDecoded + "'");

            }


        }

    }
//}
}
