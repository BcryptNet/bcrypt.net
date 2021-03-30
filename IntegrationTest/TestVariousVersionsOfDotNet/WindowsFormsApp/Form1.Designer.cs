
namespace WindowsFormsApp
{
    partial class TestForm
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.BtnBCrypt = new System.Windows.Forms.Button();
            this.lblTimer = new System.Windows.Forms.Label();
            this.lblHash = new System.Windows.Forms.Label();
            this.SuspendLayout();
            // 
            // BtnBCrypt
            // 
            this.BtnBCrypt.Location = new System.Drawing.Point(157, 177);
            this.BtnBCrypt.Name = "BtnBCrypt";
            this.BtnBCrypt.Size = new System.Drawing.Size(156, 57);
            this.BtnBCrypt.TabIndex = 0;
            this.BtnBCrypt.Text = "Run BCrypt";
            this.BtnBCrypt.UseVisualStyleBackColor = true;
            this.BtnBCrypt.Click += new System.EventHandler(this.BtnBCrypt_Click);
            // 
            // lblTimer
            // 
            this.lblTimer.AutoSize = true;
            this.lblTimer.Font = new System.Drawing.Font("Microsoft Sans Serif", 15F);
            this.lblTimer.Location = new System.Drawing.Point(152, 60);
            this.lblTimer.Name = "lblTimer";
            this.lblTimer.Size = new System.Drawing.Size(75, 25);
            this.lblTimer.TabIndex = 1;
            this.lblTimer.Text = "---------";
            this.lblTimer.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            this.lblTimer.Visible = false;
            this.lblTimer.Click += new System.EventHandler(this.label1_Click);
            // 
            // lblHash
            // 
            this.lblHash.AutoSize = true;
            this.lblHash.Font = new System.Drawing.Font("Microsoft Sans Serif", 8F);
            this.lblHash.Location = new System.Drawing.Point(94, 107);
            this.lblHash.Name = "lblHash";
            this.lblHash.Size = new System.Drawing.Size(34, 13);
            this.lblHash.TabIndex = 2;
            this.lblHash.Text = "---------";
            this.lblHash.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            this.lblHash.Visible = false;
            // 
            // TestForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(508, 346);
            this.Controls.Add(this.lblHash);
            this.Controls.Add(this.lblTimer);
            this.Controls.Add(this.BtnBCrypt);
            this.Name = "TestForm";
            this.Text = "BCrypt WinForm Test App";
            this.Load += new System.EventHandler(this.Form1_Load);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Button BtnBCrypt;
        private System.Windows.Forms.Label lblTimer;
        private System.Windows.Forms.Label lblHash;
    }
}

