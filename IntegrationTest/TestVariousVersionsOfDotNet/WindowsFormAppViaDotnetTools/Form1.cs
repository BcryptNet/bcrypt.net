using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace WindowsFormsApp
{
    public partial class TestForm : Form
    {
        public TestForm()
        {
            InitializeComponent();
        }


        private void Form1_Load(object sender, EventArgs e)
        {

        }

        private void BtnBCrypt_Click(object sender, EventArgs e)
        {
            var sw = Stopwatch.StartNew();
            var hashPassword = BCrypt.Net.BCrypt.HashPassword("changeme");
            sw.Stop();


            lblTimer.Visible = true;
            lblTimer.Text = $"{sw.ElapsedMilliseconds}ms";

            lblHash.Visible = true;
            lblHash.Text = hashPassword;
        }
    }
}
