import java.util.*;
import java.util.List;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.event.*;
import javax.swing.table.*;
import java.sql.*;
import java.security.MessageDigest;
import java.math.BigInteger;
import java.math.*;
import java.io.File;
import javax.imageio.ImageIO;

class Hash {
    public static String encode(String ip) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] messageDigest = md.digest(ip.getBytes());
            BigInteger no = new BigInteger(1, messageDigest);
            String hashtext = no.toString(16);

            while (hashtext.length() < 32) {
                hashtext = "0" + hashtext;
            }
            return hashtext;
        } catch (Exception e) {
            System.out.println(e);
            return null;
        }
    }
}

class SetUp {
    private Connection conn;

    SetUp(Connection con) {
        conn = con;
    }

    public void create() {
        try {
            Statement statement = conn.createStatement();
            ResultSet result;

            statement.execute("CREATE TABLE IF NOT EXISTS user(" + "id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,"
                    + "name VARCHAR(20) NOT NULL," + "username VARCHAR(10) NOT NULL," + "mob_no VARCHAR(15) NOT NULL,"
                    + "address VARCHAR(50) NOT NULL," + "password BINARY(64) NOT NULL,"
                    + "is_admin BOOLEAN DEFAULT false," + "cart JSON NOT NULL DEFAULT (JSON_ARRAY()));");

            statement.execute("CREATE TABLE IF NOT EXISTS category(" + "id INT PRIMARY KEY AUTO_INCREMENT NOT NULL,"
                    + "name VARCHAR(30) NOT NULL);");

            statement.execute("CREATE TABLE IF NOT EXISTS product(" + "id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,"
                    + "name VARCHAR(20) UNIQUE NOT NULL," + "description VARCHAR(100) NOT NULL," + "cat_id INT,"
                    + "FOREIGN KEY(cat_id) REFERENCES category(id)," + "photo VARCHAR(30) NOT NULL,"
                    + "price DOUBLE NOT NULL," + "discount DOUBLE," + "quantity INT NOT NULL,"
                    + "avg_rating DOUBLE DEFAULT 0," + "num_of_rating INT DEFAULT 0,"
                    + "user_id JSON NOT NULL DEFAULT (JSON_ARRAY()));");

            statement.execute("CREATE TABLE IF NOT EXISTS bill(" + "id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,"
                    + "quantity INT NOT NULL," + "total_amount DOUBLE NOT NULL,"
                    + "payment_method VARCHAR(20) NOT NULL," + "date DATE NOT NULL," + "user_id INT,"
                    + "FOREIGN KEY(user_id) REFERENCES user(id)," + "pro_id INT,"
                    + "FOREIGN KEY(pro_id) REFERENCES product(id));");

            result = statement.executeQuery("SELECT * FROM user WHERE is_admin = true;");
            if (result.next() == false) {
                statement.execute("INSERT INTO user VALUES(1, 'admin', 'admin', '1234567890', 'abc', '"
                        + Hash.encode("admin123") + "', true, NULL);");
            }

        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

}

class Login implements ActionListener {
    private Connection conn = null;

    JFrame root;
    JPanel loginFrame;
    JButton login;
    JButton signup;
    JTextField username;
    JPasswordField password;

    Login(Connection con, JFrame master) {
        conn = con;
        root = master;
        loginFrame = new JPanel();
        loginFrame.setLayout(null);
        root.add(loginFrame);

        JLabel logo = new JLabel("Image");
        JLabel title = new JLabel("Login");
        JLabel usernameLabel = new JLabel("User Name");
        username = new JTextField();
        JLabel passwordLabel = new JLabel("Password");
        password = new JPasswordField();
        login = new JButton("Login");
        JLabel signupPrompt = new JLabel("Don't have an account??");
        signup = new JButton("Sign Up");

        logo.setBounds(100, 100, 300, 200);
        title.setBounds(470, 75, 100, 50);
        usernameLabel.setBounds(450, 125, 100, 25);
        username.setBounds(580, 125, 150, 25);
        passwordLabel.setBounds(450, 175, 100, 25);
        password.setBounds(580, 175, 150, 25);
        login.setBounds(525, 225, 100, 25);
        signupPrompt.setBounds(475, 275, 150, 25);
        signup.setBounds(625, 275, 80, 25);

        loginFrame.add(logo);
        loginFrame.add(title);
        loginFrame.add(usernameLabel);
        loginFrame.add(username);
        loginFrame.add(passwordLabel);
        loginFrame.add(password);
        loginFrame.add(login);
        loginFrame.add(signupPrompt);
        loginFrame.add(signup);

        title.setFont(new Font("Serif", Font.BOLD, 25));
        login.addActionListener(this);
        signup.addActionListener(this);

        loginFrame.setVisible(true);
        loginFrame.setSize(800, 450);
    }

    public void actionPerformed(ActionEvent e) {
        if (e.getSource() == login) {
            String name = username.getText();
            String pass = new String(password.getPassword());
            try {
                Statement statement = conn.createStatement();
                ResultSet result;
                result = statement.executeQuery("SELECT password, is_admin FROM user WHERE username='" + name + "';");

                if (result.next() == false) {
                    JOptionPane.showMessageDialog(loginFrame, "Username doesn't exist", "Error",
                            JOptionPane.ERROR_MESSAGE);
                } else if (result.getString("password").equals(Hash.encode(pass))) {
                    root.remove(loginFrame);
                    if (result.getBoolean("is_admin") == true) {
                        new Admin(conn, root, name);
                    } else {
                        new Customer(root, conn, name);
                    }
                } else {
                    JOptionPane.showMessageDialog(loginFrame, "Wrong Password", "Error", JOptionPane.ERROR_MESSAGE);
                }

            } catch (Exception er) {
                System.out.println(er);
            }

        }
        if (e.getSource() == signup) {
            root.remove(loginFrame);
            new SignUp(conn, root);
        }
    }

}

class SignUp implements ActionListener {
    private Connection conn = null;
    JFrame root;
    JPanel signUpFrame;
    JButton login, signUp;
    JTextField username, name, address, contactNo;
    JPasswordField passWord, confirm;

    SignUp(Connection con, JFrame master) {
        conn = con;
        root = master;
        signUpFrame = new JPanel();
        signUpFrame.setLayout(null);
        root.add(signUpFrame);

        JLabel logo = new JLabel("Image");
        JLabel title = new JLabel("Sign Up");
        JLabel nameLabel = new JLabel("Name");
        name = new JTextField();
        JLabel uNameLabel = new JLabel("Username");
        username = new JTextField();
        JLabel addressLabel = new JLabel("Address");
        address = new JTextField();
        JLabel contactLabel = new JLabel("Contact No");
        contactNo = new JTextField();
        JLabel passWordLabel = new JLabel("Password");
        passWord = new JPasswordField();
        JLabel confirmLabel = new JLabel("Confirm Password");
        confirm = new JPasswordField();
        signUp = new JButton("Sign Up");
        JLabel loginPrompt = new JLabel("Already have an account?");
        login = new JButton("Login");

        logo.setBounds(100, 100, 300, 200);
        title.setBounds(450, 35, 100, 50);
        nameLabel.setBounds(450, 100, 140, 25);
        name.setBounds(580, 100, 150, 25);
        uNameLabel.setBounds(450, 135, 140, 25);
        username.setBounds(580, 135, 150, 25);
        addressLabel.setBounds(450, 170, 140, 25);
        address.setBounds(580, 170, 150, 25);
        contactLabel.setBounds(450, 205, 140, 25);
        contactNo.setBounds(580, 205, 150, 25);
        passWordLabel.setBounds(450, 240, 140, 25);
        passWord.setBounds(580, 240, 150, 25);
        confirmLabel.setBounds(450, 275, 140, 25);
        confirm.setBounds(580, 275, 150, 25);
        signUp.setBounds(500, 310, 140, 25);
        loginPrompt.setBounds(450, 345, 150, 30);
        login.setBounds(600, 345, 80, 30);

        title.setFont(new Font("Serif", Font.BOLD, 25));
        signUp.addActionListener(this);
        login.addActionListener(this);

        signUpFrame.add(logo);
        signUpFrame.add(title);
        signUpFrame.add(nameLabel);
        signUpFrame.add(name);
        signUpFrame.add(uNameLabel);
        signUpFrame.add(username);
        signUpFrame.add(addressLabel);
        signUpFrame.add(address);
        signUpFrame.add(contactLabel);
        signUpFrame.add(contactNo);
        signUpFrame.add(passWordLabel);
        signUpFrame.add(passWord);
        signUpFrame.add(confirmLabel);
        signUpFrame.add(confirm);
        signUpFrame.add(signUp);
        signUpFrame.add(loginPrompt);
        signUpFrame.add(login);

        signUpFrame.setVisible(true);
        signUpFrame.setSize(800, 450);
    }

    public void actionPerformed(ActionEvent e) {
        if (e.getSource() == login) {
            root.remove(signUpFrame);
            new Login(conn, root);
        } else if (e.getSource() == signUp) {
            String ipName = name.getText();
            String ipUsername = username.getText();
            String ipAddress = address.getText();
            String ipContactNo = contactNo.getText();
            String ipPass = new String(passWord.getPassword());
            String ipConfirmPass = new String(confirm.getPassword());

            try {
                Statement statement = conn.createStatement();
                ResultSet result;
                result = statement.executeQuery("SELECT * FROM user WHERE username = '" + ipUsername + "';");

                // Checking for blank fields
                if (ipName.isBlank() || ipUsername.isBlank() || ipAddress.isBlank() || ipContactNo.isBlank()
                        || ipPass.isBlank() || ipConfirmPass.isBlank()) {
                    JOptionPane.showMessageDialog(signUpFrame, "All the fields are required!!", "No blank field",
                            JOptionPane.WARNING_MESSAGE);
                }
                // Verifying if username is unique
                else if (result.next() == true) {
                    JOptionPane.showMessageDialog(signUpFrame, "Username already exists!!", "Error",
                            JOptionPane.ERROR_MESSAGE);
                } // Checking if password and confirm password are equal
                else if (!ipPass.equals(ipConfirmPass)) {
                    JOptionPane.showMessageDialog(signUpFrame, "Passwords don't match!!", "Error",
                            JOptionPane.ERROR_MESSAGE);
                }
                // If username doesn't exist then create user
                else {
                    statement.execute("INSERT INTO user(name, username, mob_no, address, password ) VALUES('" + ipName
                            + "','" + ipUsername + "','" + ipContactNo + "','" + ipAddress + "','" + Hash.encode(ipPass)
                            + "');");
                    JOptionPane.showMessageDialog(signUpFrame, "Account Created Successfully!", "Success",
                            JOptionPane.INFORMATION_MESSAGE);

                    root.remove(signUpFrame);
                    // redirecting to customer
                    new Customer(root, conn, ipUsername);

                }

            } catch (Exception er) {
                System.out.println(er);
            }
        }
    }
}

class BaseLayout implements ActionListener {
    JFrame root, changePasswordFrame;
    String appName = "App Name", uName;
    JTextField searchInp, name, address, contactNo;
    JPasswordField oldPassword, newPassword, confirmNewPassword;
    JButton cart, profile, search, logout, save, changePassword, back, confirmCP, deleteAcc;
    JPanel base, profilePanel;
    JTabbedPane tabs;
    Connection conn;
    String ipname, ipaddress, ipContactNo;
    Dictionary<Integer, String> categories = new Hashtable<Integer, String>();

    BaseLayout(JFrame master, String name, Connection con) {
        conn = con;
        root = master;
        uName = name;
        base = new JPanel();
        base.setLayout(null);
        root.add(base);

        JLabel appNameLabel = new JLabel(appName);
        searchInp = new JTextField();
        search = new JButton("Search");
        cart = new JButton("Cart");
        profile = new JButton(name);
        logout = new JButton("Logout");

        appNameLabel.setBounds(50, 5, 150, 40);
        searchInp.setBounds(200, 10, 250, 30);
        search.setBounds(450, 10, 25, 30);
        cart.setBounds(500, 10, 50, 30);
        profile.setBounds(600, 10, 100, 30);
        logout.setBounds(700, 10, 50, 30);

        base.add(appNameLabel);
        base.add(searchInp);
        base.add(search);
        base.add(cart);
        base.add(profile);
        base.add(logout);

        search.addActionListener(this);
        cart.addActionListener(this);
        profile.addActionListener(this);
        logout.addActionListener(this);

        base.setVisible(true);
        base.setSize(800, 450);

        try {
            Statement statement = conn.createStatement();
            ResultSet catResult;
            catResult = statement.executeQuery("SELECT * FROM category;");
            while (catResult.next()) {
                categories.put(catResult.getInt(1), catResult.getString(2));
            }
        } catch (Exception er) {
            System.out.println(er);
        }

    }

    public void viewProfile() {

        ResultSet res;
        try {
            Statement stm = conn.createStatement();
            res = stm.executeQuery("SELECT name,address, mob_no FROM user WHERE username = '" + uName + "';");
            if (res.next()) {
                ipname = res.getString("name");
                ipaddress = res.getString("address");
                ipContactNo = res.getString("mob_no");
            }

        } catch (Exception e) {
            System.out.println(e);
        }

        profilePanel = new JPanel();
        profilePanel.setLayout(null);
        base.setVisible(false);
        root.add(profilePanel);

        JLabel title = new JLabel("Profile");
        JLabel uNameLabel = new JLabel("Username");
        JLabel username = new JLabel(uName);
        JLabel nameLabel = new JLabel("Name");
        name = new JTextField();
        JLabel addressLabel = new JLabel("Address");
        address = new JTextField();
        JLabel contactLabel = new JLabel("Contact No");
        contactNo = new JTextField();
        save = new JButton("Save");
        changePassword = new JButton("Change Password");
        back = new JButton("Back");
        deleteAcc = new JButton("Delete Account");

        name.setText(ipname);
        address.setText(ipaddress);
        contactNo.setText(ipContactNo);

        save.addActionListener(this);
        changePassword.addActionListener(this);
        back.addActionListener(this);
        deleteAcc.addActionListener(this);

        title.setBounds(300, 35, 100, 50);
        uNameLabel.setBounds(280, 100, 140, 25);
        username.setBounds(410, 100, 150, 25);
        nameLabel.setBounds(280, 135, 140, 25);
        name.setBounds(410, 135, 150, 25);
        addressLabel.setBounds(280, 170, 140, 25);
        address.setBounds(410, 170, 150, 25);
        contactLabel.setBounds(280, 205, 140, 25);
        contactNo.setBounds(410, 205, 150, 25);
        changePassword.setBounds(280, 250, 150, 25);
        save.setBounds(340, 300, 100, 25);
        back.setBounds(20, 20, 75, 25);
        deleteAcc.setBounds(600, 350, 150, 25);

        profilePanel.add(title);
        profilePanel.add(uNameLabel);
        profilePanel.add(username);
        profilePanel.add(nameLabel);
        profilePanel.add(name);
        profilePanel.add(addressLabel);
        profilePanel.add(address);
        profilePanel.add(contactLabel);
        profilePanel.add(contactNo);
        profilePanel.add(changePassword);
        profilePanel.add(save);
        profilePanel.add(back);
        profilePanel.add(deleteAcc);

        profilePanel.setSize(800, 450);
        profile.setVisible(true);

    }

    public void changePass() {
        changePasswordFrame = new JFrame();
        changePasswordFrame.setLayout(null);

        JLabel oldPassLabel = new JLabel("Old Password");
        oldPassword = new JPasswordField();
        JLabel newPassLabel = new JLabel("New Password");
        newPassword = new JPasswordField();
        JLabel confirmNewPassLabel = new JLabel("Confirm Password");
        confirmNewPassword = new JPasswordField();
        confirmCP = new JButton("Save Password");

        oldPassLabel.setBounds(30, 20, 150, 25);
        oldPassword.setBounds(180, 20, 150, 25);
        newPassLabel.setBounds(30, 60, 150, 25);
        newPassword.setBounds(180, 60, 150, 25);
        confirmNewPassLabel.setBounds(30, 100, 150, 25);
        confirmNewPassword.setBounds(180, 100, 150, 25);
        confirmCP.setBounds(130, 150, 150, 25);

        changePasswordFrame.add(oldPassLabel);
        changePasswordFrame.add(oldPassword);
        changePasswordFrame.add(newPassLabel);
        changePasswordFrame.add(newPassword);
        changePasswordFrame.add(confirmNewPassLabel);
        changePasswordFrame.add(confirmNewPassword);
        changePasswordFrame.add(confirmCP);

        confirmCP.addActionListener(this);

        changePasswordFrame.setVisible(true);
        changePasswordFrame.setSize(400, 225);
    }

    public void actionPerformed(ActionEvent e) {
        int choice;
        if (e.getSource() == profile) {
            viewProfile();
        } else if (e.getSource() == back) {
            base.setVisible(true);
            root.remove(profilePanel);
        } else if (e.getSource() == logout) {
            try {
                choice = JOptionPane.showConfirmDialog(root,
                        "Do you really want to logout?\nThe application will be closed", "Are you sure about that?",
                        JOptionPane.YES_NO_OPTION);

                if (choice == JOptionPane.YES_OPTION) {
                    conn.close();
                    root.removeAll();
                    root.dispose();
                    System.exit(0);
                }

            } catch (Exception er) {
                System.out.println(er);
            }
        } else if (e.getSource() == changePassword) {
            changePass();
        } else if (e.getSource() == confirmCP) {
            String oldPass, newPass, confirmPass, currPass;
            oldPass = new String(oldPassword.getPassword());
            newPass = new String(newPassword.getPassword());
            confirmPass = new String(confirmNewPassword.getPassword());
            try {
                Statement statement = conn.createStatement();
                ResultSet result;
                result = statement.executeQuery("SELECT password FROM user WHERE username = '" + uName + "';");
                result.next();
                currPass = result.getString("password");

                if (currPass.equals(Hash.encode(oldPass))) {
                    if (newPass.isBlank() || confirmPass.isBlank()) {
                        JOptionPane.showMessageDialog(base, "All the fields are required!!", "No blank field",
                                JOptionPane.WARNING_MESSAGE);
                    } else if (newPass.equals(confirmPass)) {
                        statement.execute("UPDATE user SET password = '" + Hash.encode(newPass) + "' WHERE username = '"
                                + uName + "';");
                        JOptionPane.showMessageDialog(base, "Password Changed Successfully!!", "Success",
                                JOptionPane.INFORMATION_MESSAGE);
                        changePasswordFrame.dispose();
                    } else {
                        JOptionPane.showMessageDialog(base, "New and Confirm Password didn't matched!!", "Error",
                                JOptionPane.ERROR_MESSAGE);
                    }
                } else {
                    JOptionPane.showMessageDialog(base, "Old Password didn't matched!!", "Error",
                            JOptionPane.ERROR_MESSAGE);
                }

            } catch (Exception er) {
                System.out.println(er);
            }
        } else if (e.getSource() == save) {
            String upName, upAddress, upContact;
            upName = name.getText();
            upAddress = address.getText();
            upContact = contactNo.getText();
            try {
                Statement statement = conn.createStatement();
                if (upName.isBlank() || upAddress.isBlank() || upContact.isBlank()) {
                    JOptionPane.showMessageDialog(base, "All the fields are required!!", "No blank field",
                            JOptionPane.WARNING_MESSAGE);
                } else {
                    statement.execute("UPDATE user SET name='" + upName + "', address='" + upAddress + "', mob_no='"
                            + upContact + "' WHERE username = '" + uName + "';");
                    JOptionPane.showMessageDialog(root, "Changes saved Successfully!!", "Success",
                            JOptionPane.INFORMATION_MESSAGE);

                }
            } catch (Exception er) {
                System.out.println(er);
            }
        } else if (e.getSource() == deleteAcc) {
            choice = JOptionPane.showConfirmDialog(root, "Do you really want to delete Account?",
                    "Are you sure about that?", JOptionPane.YES_NO_OPTION);
            if (choice == JOptionPane.YES_OPTION) {
                try {
                    Statement statement = conn.createStatement();
                    statement.execute("DELETE FROM user WHERE username = '" + uName + "';");
                    JOptionPane.showMessageDialog(root, "Account Deleted Successfully!!", "Success",
                            JOptionPane.INFORMATION_MESSAGE);
                    conn.close();
                    root.dispose();
                } catch (Exception er) {
                    System.out.println(er);
                }
            }

        }
    }

}

class Admin extends BaseLayout {
    private Connection conn;

    Admin(Connection con, JFrame master, String name) {
        super(master, name, con);
        conn = con;

        tabs = new JTabbedPane(JTabbedPane.TOP);
        tabs.addTab("Sales", new Admin.SalesPage());
        tabs.addTab("Products", new Admin.Products());

        tabs.setBounds(0, 50, 800, 400);
        tabs.setVisible(true);
        base.add(tabs);

    }

    class SalesPage extends JScrollPane {

    }

    class Products extends JPanel implements ActionListener {
        JFrame addProdFrame, prodFrame;
        JTable productsTable;
        JButton button = new JButton();
        JLabel Name;
        JButton addProduct, saveProd, saveChg, deleteProd;
        JTextField name, des, pic, price, dis, qty;
        JComboBox<String> ctg;
        DefaultTableModel model;
        ArrayList<ArrayList<Object>> rowdata = new ArrayList<ArrayList<Object>>();
        String[] columnNames = { "Id", "Product Name", "Description", "Category", "Photos", "Price", "Discount",
                "Quantity", "Average Raiting", "Edit Product" };
        String newNameVar, newDes, newPic, newDis, newQty, newPrice, newCat;

        class ButtonRenderer extends JButton implements TableCellRenderer {
            public ButtonRenderer() {
                setOpaque(true);
            }

            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                    boolean hasFocus, int row, int column) {
                setText((value == null) ? "Edit" : value.toString());
                return this;
            }
        }

        class ButtonEditor extends DefaultCellEditor {
            private String label;

            public ButtonEditor(JCheckBox checkBox) {
                super(checkBox);
            }

            public Component getTableCellEditorComponent(JTable table, Object value, boolean isSelected, int row,
                    int column) {
                label = (value == null) ? "Edit" : value.toString();
                button.setText(label);
                return button;
            }

            public Object getCellEditorValue() {
                return new String(label);
            }
        }

        Products() {
            setLayout(null);

            ResultSet result;
            try {
                Statement statement = conn.createStatement();
                result = statement.executeQuery("SELECT * FROM product;");
                while (result.next()) {
                    rowdata.add(new ArrayList<Object>(Arrays.asList(result.getString(1), result.getString(2),
                            result.getString(3), categories.get(result.getInt(4)), result.getString(5),
                            result.getString(6), result.getString(7), result.getString(8), result.getString(9),
                            "Edit " + result.getString(1))));
                }

            } catch (Exception er) {
                System.out.println(er);
            }
            int a = rowdata.size();
            Object[][] data = new Object[a][10];

            for (int i = 0; i < a; i++) {
                data[i] = rowdata.get(i).toArray();
            }

            model = new DefaultTableModel(data, columnNames);

            productsTable = new JTable(model);
            addProduct = new JButton("Add");

            // Setting up the search
            TableRowSorter<TableModel> rowSorter = new TableRowSorter<>(productsTable.getModel());
            productsTable.setRowSorter(rowSorter);
            searchInp.getDocument().addDocumentListener(new DocumentListener() {
                @Override
                public void insertUpdate(DocumentEvent e) {
                    if (tabs.getSelectedIndex() == 1) {
                        String text = searchInp.getText();

                        if (text.trim().length() == 0) {
                            rowSorter.setRowFilter(null);
                        } else {
                            rowSorter.setRowFilter(RowFilter.regexFilter("(?i)" + text));
                        }
                    }

                }

                @Override
                public void removeUpdate(DocumentEvent e) {
                    if (tabs.getSelectedIndex() == 1) {
                        String text = searchInp.getText();

                        if (text.trim().length() == 0) {
                            rowSorter.setRowFilter(null);
                        } else {
                            rowSorter.setRowFilter(RowFilter.regexFilter("(?i)" + text));
                        }
                    }

                }

                @Override
                public void changedUpdate(DocumentEvent e) {
                    throw new UnsupportedOperationException("Not supported yet.");
                    // To change body of generated methods, choose Tools | Templates.
                }
            });

            productsTable.getColumn("Edit Product").setCellRenderer(new ButtonRenderer());
            productsTable.getColumn("Edit Product").setCellEditor(new ButtonEditor(new JCheckBox()));

            productsTable.setVisible(true);
            productsTable.setBounds(0, 0, 800, 300);
            addProduct.setBounds(550, 305, 100, 25);

            JScrollPane container = new JScrollPane(productsTable);
            container.setVisible(true);
            container.setSize(800, 300);

            button.addActionListener(this);
            addProduct.addActionListener(this);

            add(container);
            add(addProduct);
            setVisible(true);
            setSize(800, 380);

        }

        public void actionPerformed(ActionEvent e) {
            if (e.getSource() == button) {
                editProduct(e.getActionCommand());
            } else if (e.getSource() == saveChg) {
                newNameVar = Name.getText();
                newPic = pic.getText().replaceAll("\\", "\\\\");
                newDis = dis.getText();
                newQty = qty.getText();
                newPrice = price.getText();
                try {
                    // Updating values in database
                    Statement stm = conn.createStatement();
                    stm.execute("UPDATE product SET photo = '" + newPic + "',discount = " + Double.valueOf(newDis)
                            + ",quantity = " + Integer.valueOf(newQty) + ",price = " + Double.valueOf(newPrice)
                            + " WHERE name = '" + newNameVar + "' ;");

                    // Displaying success Message and closing frame
                    JOptionPane.showMessageDialog(prodFrame, "Product Updated Successfully!", "Success",
                            JOptionPane.INFORMATION_MESSAGE);
                    prodFrame.dispose();
                    // Updating values in table
                    refreshTable();
                } catch (Exception er) {
                    System.out.println(er);
                }
            } else if (e.getSource() == addProduct) {
                addProducts();
            } else if (e.getSource() == saveProd) {
                String newname = name.getText();
                String newdes = des.getText();
                String newpic = pic.getText().replaceAll("\\", "\\\\");
                String newprice = price.getText();
                String newdis = dis.getText();
                String newqty = qty.getText();
                String newcat = ctg.getItemAt(ctg.getSelectedIndex());

                if (newname.isBlank() || newdes.isBlank() || newpic.isBlank() || newprice.isBlank() || newdis.isBlank()
                        || newqty.isBlank()) {
                    JOptionPane.showMessageDialog(base, "All the fields are required!!", "No blank field",
                            JOptionPane.WARNING_MESSAGE);
                }
                try {
                    Statement statement = conn.createStatement();
                    ResultSet result = statement.executeQuery("SELECT id FROM category WHERE name = '" + newcat + "';");
                    result.next();
                    statement.execute(
                            "INSERT INTO product(name, description, cat_id, photo, price, discount, quantity) VALUES ('"
                                    + newname + "', '" + newdes + "', '" + result.getInt(1) + "', '" + newpic + "', '"
                                    + Double.valueOf(newprice) + "', '" + Double.valueOf(newdis) + "', '"
                                    + Integer.valueOf(newqty) + "');");
                    addProdFrame.dispose();
                    refreshTable();
                    JOptionPane.showMessageDialog(base, "Product Added Successfully!", "Success",
                            JOptionPane.INFORMATION_MESSAGE);

                } catch (Exception er) {
                    System.out.println(er);
                }
            } else if (e.getSource() == deleteProd) {
                StringTokenizer str = new StringTokenizer(e.getActionCommand(), " ");
                System.out.println(str.nextToken());

                try {
                    Statement statement = conn.createStatement();
                    int choice = JOptionPane.showConfirmDialog(base, "Do you really want to delete this product",
                            "DELETE", JOptionPane.YES_NO_OPTION);
                    if (choice == JOptionPane.YES_OPTION) {
                        statement.execute("DELETE FROM product WHERE id=" + Integer.valueOf(str.nextToken()) + ";");
                        prodFrame.dispose();
                        refreshTable();
                    }
                } catch (Exception er) {
                    System.out.println("Delete Product: " + er);
                }
            }
        }

        public void editProduct(String btnName) {
            StringTokenizer str = new StringTokenizer(btnName, " ");
            // discarding first token
            str.nextToken();
            int id = Integer.valueOf(str.nextToken());
            ResultSet res;
            try {
                Statement stm = conn.createStatement();
                res = stm.executeQuery("SELECT * FROM product WHERE id = " + id + ";");
                res.next();
                newNameVar = res.getString("name");
                newDes = res.getString("description");
                newPic = res.getString("photo");
                newDis = res.getString("discount");
                newQty = res.getString("quantity");
                newPrice = res.getString("price");
                newCat = categories.get(res.getInt("cat_id"));

            } catch (Exception e) {
                System.out.println(e);
            }
            prodFrame = new JFrame();
            prodFrame.setLayout(null);

            // Title
            JLabel title = new JLabel("Edit Product");
            title.setBounds(150, 10, 150, 25);

            // name
            JLabel nameLab = new JLabel("Name: ");
            nameLab.setBounds(100, 50, 130, 25);

            Name = new JLabel(newNameVar);
            Name.setBounds(210, 50, 80, 25);

            // description
            JLabel desLab = new JLabel("Description: ");
            desLab.setBounds(100, 85, 130, 25);

            JLabel desc = new JLabel(newDes);
            desc.setBounds(210, 85, 80, 25);

            // Image link
            JLabel picLab = new JLabel("Image link: ");
            picLab.setBounds(100, 120, 130, 25);

            pic = new JTextField(newPic);
            pic.setBounds(210, 120, 80, 25);

            // price
            JLabel priceLab = new JLabel("Price: ");
            priceLab.setBounds(100, 155, 130, 25);

            price = new JTextField(newPrice);
            price.setBounds(210, 155, 80, 25);

            // discount
            JLabel disLab = new JLabel("Discount: ");
            disLab.setBounds(100, 190, 130, 25);

            dis = new JTextField(newDis);
            dis.setBounds(210, 190, 80, 25);

            // quantity
            JLabel qtyLab = new JLabel("Quantity: ");
            qtyLab.setBounds(100, 225, 130, 25);

            qty = new JTextField(newQty);
            qty.setBounds(210, 225, 80, 25);

            // category

            JLabel ctgLab = new JLabel("Category: ");
            ctgLab.setBounds(100, 260, 130, 25);

            JLabel ctg = new JLabel(newCat);
            ctg.setBounds(210, 260, 80, 25);

            // save product button
            saveChg = new JButton("Save");
            saveChg.setBounds(130, 300, 150, 25);
            saveChg.addActionListener(this);

            // delete product button
            deleteProd = new JButton("Delete " + id);
            deleteProd.setBounds(130, 330, 150, 25);
            deleteProd.addActionListener(this);

            // Add components to frame
            prodFrame.add(title);
            prodFrame.add(nameLab);
            prodFrame.add(Name);
            prodFrame.add(desLab);
            prodFrame.add(desc);
            prodFrame.add(picLab);
            prodFrame.add(pic);
            prodFrame.add(priceLab);
            prodFrame.add(price);
            prodFrame.add(disLab);
            prodFrame.add(dis);
            prodFrame.add(qtyLab);
            prodFrame.add(qty);
            prodFrame.add(ctgLab);
            prodFrame.add(ctg);
            prodFrame.add(saveChg);
            prodFrame.add(deleteProd);

            prodFrame.setSize(400, 410);
            prodFrame.setVisible(true);
            prodFrame.setResizable(false);
        }

        public void refreshTable() {
            try {
                Statement stm = conn.createStatement();
                ResultSet res = stm.executeQuery("SELECT * FROM product");
                rowdata.clear();
                while (res.next()) {
                    rowdata.add(new ArrayList<Object>(Arrays.asList(res.getString(1), res.getString(2),
                            res.getString(3), categories.get(res.getInt(4)), res.getString(5), res.getString(6),
                            res.getString(7), res.getString(8), res.getString(9), "Edit " + res.getString(1))));
                }
            } catch (Exception er) {
                System.out.println("Refresh: " + er);
            }
            int a = rowdata.size();
            Object[][] tableData = new Object[a][10];

            // adding actionListener and converting to array
            for (int i = 0; i < a; i++) {
                tableData[i] = rowdata.get(i).toArray();
            }

            model.setDataVector(tableData, columnNames);

            productsTable.getColumn("Delete Product").setCellRenderer(new ButtonRenderer());
            productsTable.getColumn("Delete Product").setCellEditor(new ButtonEditor(new JCheckBox()));

        }

        public void addProducts() {
            addProdFrame = new JFrame();
            addProdFrame.setLayout(null);
            String[] cat = new String[categories.size()];

            JLabel title = new JLabel("Add Products");
            JLabel nameLab = new JLabel("Name");
            name = new JTextField();
            JLabel desLab = new JLabel("Description");
            des = new JTextField();
            JLabel picLab = new JLabel("Pictures");
            pic = new JTextField();
            JLabel priceLab = new JLabel("Price");
            price = new JTextField();
            JLabel disLab = new JLabel("Discount");
            dis = new JTextField();
            JLabel qtyLab = new JLabel("Quantity");
            qty = new JTextField();
            JLabel ctgLab = new JLabel("Catagory");
            Enumeration<Integer> catkey = categories.keys();
            for (int i = 0; i < categories.size(); i++) {
                cat[i] = categories.get(catkey.nextElement());
            }
            ctg = new JComboBox<String>(cat);
            saveProd = new JButton("Add Product");

            title.setBounds(150, 10, 100, 30);
            nameLab.setBounds(100, 50, 100, 25);
            name.setBounds(210, 50, 100, 25);
            desLab.setBounds(100, 85, 100, 25);
            des.setBounds(210, 85, 100, 25);
            picLab.setBounds(100, 120, 100, 25);
            pic.setBounds(210, 120, 100, 25);
            priceLab.setBounds(100, 155, 100, 25);
            price.setBounds(210, 155, 100, 25);
            disLab.setBounds(100, 190, 100, 25);
            dis.setBounds(210, 190, 100, 25);
            qtyLab.setBounds(100, 225, 100, 25);
            qty.setBounds(210, 225, 100, 25);
            ctgLab.setBounds(100, 260, 100, 25);
            ctg.setBounds(210, 260, 100, 25);
            saveProd.setBounds(135, 310, 150, 25);

            addProdFrame.add(title);
            addProdFrame.add(nameLab);
            addProdFrame.add(name);
            addProdFrame.add(desLab);
            addProdFrame.add(des);
            addProdFrame.add(picLab);
            addProdFrame.add(pic);
            addProdFrame.add(priceLab);
            addProdFrame.add(price);
            addProdFrame.add(disLab);
            addProdFrame.add(dis);
            addProdFrame.add(qtyLab);
            addProdFrame.add(qty);
            addProdFrame.add(ctgLab);
            addProdFrame.add(ctg);
            addProdFrame.add(saveProd);

            saveProd.addActionListener(this);

            addProdFrame.setSize(400, 400);
            addProdFrame.setVisible(true);
            addProdFrame.setResizable(false);
        }

    }
}

class Customer extends BaseLayout {
    JPanel prodDetail, cartPanel;
    JScrollPane cartScrollPane, billingPane;
    JLabel GrandTotal;
    JButton backButton, buyNow;
    double gTotal = 0;
    ArrayList<Integer> cartQuantity = new ArrayList<Integer>();
    List<String> carts;
    Connection conn;
    String[] cat;

    Customer(JFrame master, Connection con, String name) {
        super(master, name, con);
        conn = con;
        cat = new String[categories.size()];
        Enumeration<Integer> catKey = categories.keys();
        for (int i = 0; i < categories.size() && catKey.hasMoreElements(); i++) {
            cat[i] = categories.get(catKey.nextElement());
        }
        tabs = new JTabbedPane(JTabbedPane.TOP);

        // Adding all-categories tab
        tabs.addTab("All", new JScrollPane());
        for (int i = 0; i < cat.length; i++) {
            tabs.addTab(cat[i], new JScrollPane());
        }

        tabs.setBounds(0, 60, 785, 350);

        base.add(tabs);

        // Getting Values From Cart
        getCart();

        // Setting up products
        try {
            Statement stm = conn.createStatement();
            ResultSet res;
            res = stm.executeQuery("SELECT * FROM product;");
            product(res, (JScrollPane) tabs.getComponent(0));
        } catch (Exception er) {
            System.out.println("In Customer Constructor: " + er);
        }

        // Adding a change tab event listener
        tabs.addChangeListener(new ChangeListener() {
            public void stateChanged(ChangeEvent e) {
                int selected = tabs.getSelectedIndex();
                try {
                    Statement stm = conn.createStatement();
                    ResultSet res;
                    JScrollPane selPane = (JScrollPane) tabs.getSelectedComponent();
                    if (selected == 0) {
                        // Fetch all products
                        res = stm.executeQuery("SELECT * FROM product;");
                        product(res, selPane);

                    } else {
                        // Fetch product of specific category
                        res = stm.executeQuery(
                                "SELECT * FROM product WHERE cat_id = (SELECT id FROM category WHERE name ='"
                                        + cat[selected - 1] + "');");
                        product(res, selPane);
                    }
                } catch (Exception er) {
                    System.out.println("In state Change function(Customer)" + er);
                }

            }
        });

        searchInp.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                searchFunc();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                searchFunc();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                throw new UnsupportedOperationException("Not supported yet.");
                // To change body of generated methods, choose Tools | Templates.
            }
        });
    }

    public void actionPerformed(ActionEvent e) {
        super.actionPerformed(e);
        if (e.getSource() == cart) {
            new Cart();
        }
    }

    public void searchFunc() {

        try {
            Statement stm = conn.createStatement();
            ResultSet res;
            if (tabs.getSelectedIndex() == 0) {
                res = stm.executeQuery(
                        "SELECT * FROM product WHERE name LIKE '" + "%" + searchInp.getText() + "%" + "';");
            } else {
                String categ = cat[tabs.getSelectedIndex() - 1];
                res = stm.executeQuery("SELECT * FROM product WHERE cat_id = (SELECT id FROM category WHERE name ='"
                        + categ + "') AND name LIKE '" + "%" + searchInp.getText() + "%" + "';");
            }
            product(res, (JScrollPane) tabs.getSelectedComponent());
        } catch (Exception er) {
            System.out.println("In InsertUpdate function: " + er);
        }
    }

    public void product(ResultSet data, JScrollPane parent) {
        JPanel prod;
        parent.setLayout(new ScrollPaneLayout());

        JPanel box = new JPanel();
        box.setLayout(null);
        try {
            data.last();
            int num = data.getRow();
            int x = 20, y = 10, height = 200, width = 170, itr = 0;
            data.first();
            if (num > 0) {
                do {
                    prod = new Prod(data);
                    prod.setBounds(x, y, width, height);
                    box.add(prod);
                    itr++;
                    if (itr == 4) {
                        y += 210;
                        x = 20;
                        itr = 0;
                    } else {
                        x += 180;
                    }
                } while (data.next());

            } else {
                JLabel noProd = new JLabel("There are no Products in this category");
                noProd.setBounds(350, 140, 200, 30);
                box.add(noProd);
            }
            // Configuring internal pane
            box.setVisible(true);
            box.setPreferredSize(new Dimension(750, y + 225));
            // Configuring Scroll Pane
            parent.setViewportView(box);
            parent.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
            parent.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
            parent.getViewport().setPreferredSize(new Dimension(780, 300));
            parent.setVisible(true);

        } catch (Exception er) {
            System.out.println("In Product function: " + er);
        }

    }

    class Prod extends JPanel implements ActionListener {
        ResultSet data;
        int prodId;
        JButton view, addToCart;

        Prod(ResultSet res) {
            data = res;
            JLabel name, photo, price, discount;

            setLayout(null);
            try {
                name = new JLabel(data.getString("name"));
                name.setBounds(10, 10, 100, 25);

                price = new JLabel(data.getString("price"));
                price.setBounds(10, 105, 100, 30);

                discount = new JLabel(data.getString("discount") + "%");
                discount.setBounds(120, 105, 80, 20);

                photo = new JLabel("Photo");
                // photo = new JLabel(new ImageIcon(ImageIO.read(new
                // File(data.getString("photo")))));
                photo.setBounds(10, 45, 150, 50);

                prodId = data.getInt("id");

                view = new JButton("View");
                view.setBounds(35, 135, 100, 25);
                view.addActionListener(this);

                if (carts.contains('"' + String.valueOf(prodId) + '"')) {
                    addToCart = new JButton("-");
                } else {
                    addToCart = new JButton("+");
                }
                addToCart.setBounds(35, 170, 100, 25);
                addToCart.addActionListener(this);

                add(photo);
                add(name);
                add(price);
                add(discount);
                add(view);
                add(addToCart);

            } catch (Exception er) {
                System.out.println("In Prod Constructor: " + er);
            }

            setVisible(true);
            setBorder(BorderFactory.createLineBorder(Color.black));
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            if (e.getSource() == view) {
                getCart();
                // Creating the new frame for product detail
                prodDetail = new ProductDetail(prodId);
                prodDetail.setSize(800, 450);
                prodDetail.setVisible(true);
                prodDetail.setLayout(null);
                root.add(prodDetail);
                base.setVisible(false);
            } else if (e.getSource() == addToCart) {
                try {
                    if (e.getActionCommand().contains("+")) {
                        addedToCart(prodId);
                        addToCart.setText("-");
                    } else if (e.getActionCommand().contains("-")) {
                        removedFromCart(prodId);
                        addToCart.setText("+");
                    }
                } catch (Exception er) {
                    System.out.println("Prod ActionPerformed: " + er);
                }
                // Refreshing cart
                getCart();

            }
        }
    }

    class ProductDetail extends JPanel implements ActionListener {

        JButton backBtn, addToCart, decQuantity, incQuantity;
        JTextField quantity;
        int prodId;
        int maxQuant;

        ProductDetail(int id) {
            JLabel name, photo, price, discount, des;
            prodId = id;

            try {
                Statement stm = conn.createStatement();
                ResultSet data = stm.executeQuery("SELECT * FROM product WHERE id = " + id + ";");
                data.next();

                maxQuant = data.getInt("quantity");

                photo = new JLabel("photo");
                // photo = new JLabel(new ImageIcon(ImageIO.read(new
                // File(data.getString("photo")))));
                photo.setBounds(85, 75, 300, 300);

                name = new JLabel(data.getString("name"));
                name.setBounds(550, 150, 100, 100);

                price = new JLabel(data.getString("price"));
                price.setBounds(550, 250, 100, 100);

                discount = new JLabel(data.getString("discount") + "%");
                discount.setBounds(550, 300, 100, 100);

                des = new JLabel(data.getString("description"));
                des.setBounds(550, 200, 100, 100);

                backBtn = new JButton("Back");
                backBtn.setBounds(10, 10, 100, 25);
                backBtn.addActionListener(this);

                buyNow = new JButton("Buy Now");
                buyNow.setBounds(650, 360, 100, 25);
                buyNow.addActionListener(this);

                decQuantity = new JButton("-");
                decQuantity.setBounds(650, 330, 33, 25);
                decQuantity.addActionListener(this);
                decQuantity.setEnabled(false);

                quantity = new JTextField();
                quantity.setText("1");
                quantity.setBounds(683, 330, 34, 25);
                quantity.setEditable(false);

                incQuantity = new JButton("+");
                incQuantity.setBounds(717, 330, 33, 25);
                incQuantity.addActionListener(this);

                if (carts.contains('"' + data.getString("id") + '"')) {
                    addToCart = new JButton("-");
                } else {
                    addToCart = new JButton("+");
                }
                addToCart.setBounds(670, 10, 100, 25);
                addToCart.addActionListener(this);

                add(name);
                add(price);
                add(discount);
                add(photo);
                add(backBtn);
                add(addToCart);
                add(buyNow);
                add(decQuantity);
                add(quantity);
                add(incQuantity);

            } catch (Exception er) {
                System.out.println("In product detail constructor: " + er);
            }
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            getCart();
            int qty = Integer.valueOf(quantity.getText());
            if (e.getSource() == backBtn) {
                int prev = tabs.getSelectedIndex();
                tabs.setSelectedIndex((prev % categories.size()) + 1);
                tabs.setSelectedIndex(prev);

                base.setVisible(true);
                root.remove(prodDetail);
            } else if (e.getSource() == addToCart) {
                if (e.getActionCommand().contentEquals("+")) {
                    addedToCart(prodId);
                    addToCart.setText("-");
                } else if (e.getActionCommand().contentEquals("-")) {
                    removedFromCart(prodId);
                    addToCart.setText("+");
                }
            } else if (e.getSource() == decQuantity) {
                if (qty <= 2) {
                    decQuantity.setEnabled(false);
                }
                quantity.setText("" + (qty - 1));
                incQuantity.setEnabled(true);
            } else if (e.getSource() == incQuantity) {
                if (qty < maxQuant) {
                    decQuantity.setEnabled(true);
                    quantity.setText("" + (qty + 1));
                } else {
                    incQuantity.setEnabled(false);
                }

            } else if (e.getSource() == buyNow) {
                ArrayList<Integer> prodQty = new ArrayList<Integer>();
                List<String> prod = new ArrayList<String>();
                prod.add("" + '"' + prodId + '"');
                prodQty.add(qty);

                setVisible(false);
                billingPane = new JScrollPane(new Customer.Billing(prod, prodQty, true));
                billingPane.setVisible(true);
                billingPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
                billingPane.setBounds(0, 0, 785, 420);
                root.add(billingPane);
            }

        }

    }

    public void addedToCart(int id) {
        try {
            Statement stm = conn.createStatement();
            stm.execute("UPDATE user SET cart= JSON_ARRAY_APPEND(`cart`, '$', '" + id + "') WHERE username='" + uName
                    + "';");
        } catch (Exception er) {
            System.out.println("Add Cart: " + er);
        }
    }

    public void removedFromCart(int id) {
        try {
            Statement stm = conn.createStatement();
            stm.execute("UPDATE user SET cart= JSON_REMOVE(`cart`, REPLACE(JSON_SEARCH(`cart`, 'one', '" + id
                    + "'), '\"', '')) WHERE username='" + uName + "';");
        } catch (Exception er) {
            System.out.println("Remove Cart: " + er);
        }
    }

    public void getCart() {
        try {
            Statement stm = conn.createStatement();
            ResultSet res;
            res = stm.executeQuery("SELECT cart FROM user WHERE username = '" + uName + "';");
            res.next();

            String tempCart = res.getString("cart").substring(1, res.getString("cart").length() - 1);
            String[] tempCart1 = tempCart.split(", ");
            carts = new ArrayList<String>(Arrays.asList(tempCart1));

        } catch (Exception er) {
            System.out.println("Getting Cart: " + er);
        }
    }

    public void populateCart() {
        int x = 0, y = 10, width = 780, height = 180;
        cartPanel.removeAll();
        for (int i = 0; i < carts.size(); i++) {
            if (carts.get(i).replace('"', ' ').strip().length() == 0) {
                break;
            }
            JPanel temp = new Customer.cartProdDetail(Integer.valueOf(carts.get(i).replace('"', ' ').strip()));
            temp.setBounds(x, y, width, height);
            y += height;
            cartPanel.add(temp);
        }
        cartPanel.setPreferredSize(new Dimension(width, y + height));
    }

    class Cart implements ActionListener {

        Cart() {
            gTotal = 0;
            for (int i = 0; i < carts.size(); i++) {
                cartQuantity.add(1);
            }
            // Setting up cart page
            cartPanel = new JPanel();
            cartPanel.setLayout(null);
            populateCart();
            cartPanel.setVisible(true);

            // Setting up scroll pane
            cartScrollPane = new JScrollPane(cartPanel);
            cartScrollPane.setVisible(true);
            cartScrollPane.setBounds(0, 50, 785, 300);
            cartScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);

            // adding back button
            backButton = new JButton("<-");
            backButton.setBounds(10, 10, 50, 25);
            backButton.addActionListener(this);

            buyNow = new JButton("Buy Now");
            buyNow.setBounds(650, 360, 100, 25);
            buyNow.addActionListener(this);

            if (carts.get(0) == "") {
                JLabel empty = new JLabel("Cart is Empty");
                empty.setBounds(100, 100, 200, 30);
                cartPanel.add(empty);
                buyNow.setVisible(false);
            }

            double gTotal = setGrandTotal(0);

            GrandTotal = new JLabel("" + gTotal);
            GrandTotal.setBounds(550, 360, 100, 25);

            base.setVisible(false);
            root.add(backButton);
            root.add(GrandTotal);
            root.add(buyNow);
            root.add(cartScrollPane);

        }

        @Override
        public void actionPerformed(ActionEvent e) {
            if (e.getSource() == backButton) {
                int prev = tabs.getSelectedIndex();
                tabs.setSelectedIndex((prev % categories.size()) + 1);
                tabs.setSelectedIndex(prev);
                cartScrollPane.setVisible(false);
                base.setVisible(true);
                root.remove(cartScrollPane);
                root.remove(buyNow);
                root.remove(backButton);
                root.remove(GrandTotal);
            } else if (e.getSource() == buyNow) {
                cartScrollPane.setVisible(false);
                buyNow.setVisible(false);
                backButton.setVisible(false);
                GrandTotal.setVisible(false);
                billingPane = new JScrollPane(new Customer.Billing(carts, cartQuantity, false));
                billingPane.setVisible(true);
                billingPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
                billingPane.setBounds(0, 0, 785, 420);
                root.add(billingPane);
            }
        }

    }

    public double setGrandTotal(double total) {
        gTotal += total;
        return gTotal;
    }

    public double setGrandTotalDec(double total) {
        gTotal -= total;
        return gTotal;
    }

    class cartProdDetail extends JPanel implements ActionListener {
        JButton decQuantity, incQuantity, remove;
        JLabel photo, name, price, discount, grandTotalLabel, tPrice, tDiscount, total;
        JTextField quantity;
        int id, quanIndex = 0, maxQuant, tqty;
        double priceVal, discountVal, discountedVal, tTPrice, tPriceVal, tdiscountVal;

        cartProdDetail(int pId) {
            setLayout(null);
            id = pId;
            tqty = cartQuantity.get(carts.indexOf("" + '"' + id + '"'));

            try {
                Statement stm = conn.createStatement();
                ResultSet data = stm.executeQuery("SELECT * FROM product WHERE id = " + id + ";");
                data.next();

                priceVal = data.getInt("price");
                discountVal = data.getInt("discount");
                tPriceVal = data.getInt("price");
                tdiscountVal = data.getInt("discount");

                maxQuant = data.getInt("quantity");

                photo = new JLabel("Photo");
                // photo = new JLabel(new ImageIcon(ImageIO.read(new
                // File(data.getString("photo")))));
                photo.setBounds(15, 10, 130, 130);

                name = new JLabel(data.getString("name"));
                name.setBounds(160, 10, 100, 50);

                price = new JLabel("\u20B9" + " " + priceVal);
                price.setBounds(180, 50, 100, 50);

                discount = new JLabel(discountVal + "%");
                discount.setBounds(180, 80, 100, 50);

                quantity = new JTextField();
                quantity.setText("" + tqty);
                quantity.setBounds(500, 60, 40, 30);
                quantity.setEditable(false);

                decQuantity = new JButton("-");
                decQuantity.setBounds(500, 30, 40, 30);
                decQuantity.addActionListener(this);
                if (tqty == 1) {
                    decQuantity.setEnabled(false);
                }

                incQuantity = new JButton("+");
                incQuantity.setBounds(500, 90, 40, 30);
                incQuantity.addActionListener(this);

                remove = new JButton("x");
                remove.setBounds(755, 0, 25, 25);
                remove.addActionListener(this);

                grandTotalLabel = new JLabel("Grand Total");
                grandTotalLabel.setBounds(560, 80, 100, 50);

                tPrice = new JLabel("" + (priceVal * tqty));
                tPrice.setBounds(680, 20, 150, 50);

                discountedVal = ((priceVal * tqty) * (discountVal / 100));

                tDiscount = new JLabel("-" + discountedVal);
                tDiscount.setBounds(680, 50, 100, 50);

                total = new JLabel("" + ((priceVal * tqty) - discountedVal));
                total.setBounds(680, 80, 150, 50);

                add(name);
                add(price);
                add(discount);
                add(photo);
                add(decQuantity);
                add(quantity);
                add(incQuantity);
                add(remove);
                add(grandTotalLabel);
                add(tPrice);
                add(tDiscount);
                add(total);

                setGrandTotal((double) (Math.round(((priceVal * tqty) - discountedVal) * 100)) / 100);

            } catch (Exception er) {
                System.out.println("In cartProdDetail detail constructor: " + er);
            }
            setVisible(true);
            setBorder(BorderFactory.createLineBorder(Color.black));

        }

        @Override
        public void actionPerformed(ActionEvent e) {
            int qty = Integer.valueOf(quantity.getText());
            tTPrice = tPriceVal - (tPriceVal * (tdiscountVal / 100));

            if (e.getSource() == decQuantity) {
                if (qty <= 2) {
                    decQuantity.setEnabled(false);
                }
                quantity.setText("" + (qty - 1));
                gTotal = setGrandTotalDec(tTPrice);
                GrandTotal.setText("" + gTotal);
                cartQuantity.set(carts.indexOf("" + '"' + id + '"'),
                        (cartQuantity.get(carts.indexOf("" + '"' + id + '"')) - 1));
                incQuantity.setEnabled(true);
            } else if (e.getSource() == incQuantity) {
                if (qty < maxQuant) {
                    decQuantity.setEnabled(true);
                    quantity.setText("" + (qty + 1));
                    gTotal = setGrandTotal(tTPrice);
                    GrandTotal.setText("" + gTotal);
                    cartQuantity.set(carts.indexOf("" + '"' + id + '"'),
                            (cartQuantity.get(carts.indexOf("" + '"' + id + '"')) + 1));
                } else {
                    incQuantity.setEnabled(false);
                }
            } else if (e.getSource() == remove) {
                gTotal = setGrandTotalDec(tTPrice * qty);
                GrandTotal.setText("" + gTotal);
                removedFromCart(id);
                cartPanel.removeAll();
                getCart();
                cartScrollPane.setVisible(false);
                cartScrollPane.setVisible(true);
                populateCart();
            }

            // calculating necessary values
            qty = Integer.valueOf(quantity.getText());
            priceVal = Double.valueOf(price.getText().replace('\u20B9', ' ').strip()) * qty;

            // updating the total price
            tPrice.setText("" + priceVal);
            discountedVal = Double.valueOf(tPrice.getText()) * (discountVal / 100);
            tDiscount.setText("-" + (double) (Math.round(discountedVal * 100)) / 100);
            total.setText("" + (double) (Math.round((priceVal - discountedVal) * 100)) / 100);

        }
    }

    class Billing extends JPanel implements ActionListener {
        List<String> products;
        ArrayList<Integer> prodQuant;
        ArrayList<Double> totals;
        JTextField addr, phone;
        JPanel productsDetailPanel;
        JScrollPane productsDetailScroll;
        JRadioButton upi, cards, cod;
        ButtonGroup bg;
        JButton confirm, back;
        boolean isView;
        double total = 0, totdisc = 0, grandTotal = 0, temptotal = 0;

        Billing(List<String> product, ArrayList<Integer> quant, boolean isVw) {
            products = product;
            prodQuant = quant;
            isView = isVw;
            totals = new ArrayList<Double>();

            setLayout(null);
            try {
                Statement stm = conn.createStatement();
                ResultSet res = stm.executeQuery("SELECT * FROM user WHERE username = '" + uName + "';");
                res.next();
                JLabel name = new JLabel(uName);
                JLabel addrLabel = new JLabel("Address");
                addr = new JTextField();
                JLabel phoneLabel = new JLabel("Phone Number");
                phone = new JTextField();
                upi = new JRadioButton("UPI");
                cards = new JRadioButton("Cards");
                cod = new JRadioButton("Cash On Delivery");
                confirm = new JButton("Buy Now");
                back = new JButton("Back");

                productsDetailPanel = new JPanel();
                productsDetailPanel.setLayout(null);

                int y = 5;
                for (int i = 0; i < products.size(); i++) {
                    ResultSet prodDetail = stm
                            .executeQuery("Select * FROM product WHERE id = " + products.get(i) + ";");
                    prodDetail.next();
                    JLabel tempProd = new JLabel(prodDetail.getString("name"));
                    JLabel tempPrice = new JLabel(prodDetail.getString("price"));
                    JLabel tempx = new JLabel("x");
                    JLabel tempqty = new JLabel("" + prodQuant.get(i));
                    JLabel tempdis = new JLabel("-" + prodDetail.getString("discount") + "%");

                    temptotal = ((prodDetail.getInt("price") * prodQuant.get(i))
                            - ((prodDetail.getInt("price") * prodQuant.get(i))
                                    * (prodDetail.getDouble("discount") / 100)));
                    JLabel tempTotal = new JLabel("" + temptotal);
                    totals.add(temptotal);

                    tempProd.setBounds(5, y, 150, 25);
                    tempPrice.setBounds(160, y, 150, 25);
                    tempx.setBounds(310, y, 20, 25);
                    tempqty.setBounds(330, y, 150, 25);
                    tempdis.setBounds(480, y, 150, 25);
                    tempTotal.setBounds(630, y, 150, 25);
                    y += 35;

                    productsDetailPanel.add(tempProd);
                    productsDetailPanel.add(tempPrice);
                    productsDetailPanel.add(tempx);
                    productsDetailPanel.add(tempqty);
                    productsDetailPanel.add(tempdis);
                    productsDetailPanel.add(tempTotal);

                    total += prodDetail.getInt("price") * prodQuant.get(i);
                    totdisc += (prodDetail.getInt("price") * prodQuant.get(i))
                            * (prodDetail.getDouble("discount") / 100);

                }
                productsDetailPanel.setVisible(true);
                productsDetailPanel.setPreferredSize(new Dimension(750, 150));

                productsDetailScroll = new JScrollPane(productsDetailPanel);
                productsDetailScroll.setVisible(true);
                productsDetailScroll.setBounds(10, 0, 750, 150);
                productsDetailScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);

                grandTotal = total - totdisc;
                JLabel totProd = new JLabel("Total Books: " + products.size());
                JLabel totalLabel = new JLabel("" + total);
                JLabel totdiscLabel = new JLabel("-" + totdisc);
                JLabel grandTotalLabel = new JLabel("Total: " + grandTotal);

                bg = new ButtonGroup();
                bg.add(upi);
                bg.add(cards);
                bg.add(cod);

                back.addActionListener(this);
                confirm.addActionListener(this);

                back.setBounds(200, 200, 100, 25);
                confirm.setBounds(300, 200, 100, 25);

                add(name);
                add(addrLabel);
                add(addr);
                add(phoneLabel);
                add(phone);
                add(upi);
                add(cards);
                add(cod);
                add(confirm);
                add(productsDetailScroll);
                add(totProd);
                add(totalLabel);
                add(totdiscLabel);
                add(grandTotalLabel);
                add(back);

            } catch (Exception er) {
                System.out.println("Billing Const: " + er);
            }
            setVisible(true);
            setPreferredSize(new Dimension(790, 420));

        }

        @Override
        public void actionPerformed(ActionEvent e) {
            if (e.getSource() == back) {
                if (isView) {
                    prodDetail.setVisible(true);
                } else {
                    cartScrollPane.setVisible(true);
                    buyNow.setVisible(true);
                    backButton.setVisible(true);
                    GrandTotal.setVisible(true);
                }
                billingPane.setVisible(false);
                root.remove(billingPane);
            } else if (e.getSource() == confirm) {

                String selected = "";
                if (upi.isSelected()) {
                    selected = "UPI";
                } else if (cards.isSelected()) {
                    selected = "Cards";
                } else {
                    selected = "Cash on Delivery";
                }

                try {
                    Statement stm = conn.createStatement();
                    for (int i = 0; i < products.size(); i++) {
                        stm.execute("UPDATE product SET quantity = quantity -" + prodQuant.get(i) + " WHERE id = "
                                + Integer.valueOf(products.get(i).replace('"', ' ').strip()) + ";");
                        stm.execute(
                                "INSERT INTO bill (quantity, total_amount, payment_method, date, user_id, pro_id) VALUES ("
                                        + prodQuant.get(i) + ", " + totals.get(i) + ", '" + selected + "', (DATE)"
                                        + new java.sql.Date((new java.util.Date()).getTime()) + ", '" + uName + "', "
                                        + Integer.valueOf(products.get(i).replace('"', ' ').strip()) + ");");

                    }
                    if (!isView) {
                        stm.execute("UPDATE user SET cart = (JSON_ARRAY()) WHERE username = '" + uName + "';");
                    }
                    JOptionPane.showMessageDialog(root, "Order Placed Successfully", "Success",
                            JOptionPane.INFORMATION_MESSAGE);
                    root.remove(billingPane);
                    if (isView) {
                        root.remove(prodDetail);
                    } else {
                        root.remove(cartScrollPane);
                        root.remove(buyNow);
                        root.remove(backButton);
                        root.remove(GrandTotal);
                    }
                    getCart();
                    int prev = tabs.getSelectedIndex();
                    tabs.setSelectedIndex((prev % categories.size()) + 1);
                    tabs.setSelectedIndex(prev);
                    base.setVisible(true);

                } catch (Exception er) {
                    System.out.println("Decrease Quantity: " + er);
                }
            }

        }
    }
}

class shoppingApp {
    public static void main(String[] args) {
        try {
            Class.forName("com.mysql.jdbc.Driver");
            Connection conn = DriverManager.getConnection(
                    "jdbc:mysql://localhost:3306/shopping_app?characterEncoding=latin1&useConfigs=maxPerformance",
                    "user1", "aryan1212");
            JFrame root = new JFrame();
            root.setLayout(null);
            root.setSize(800, 450);
            root.setResizable(false);
            root.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            root.setVisible(true);

            new SetUp(conn).create();
            new Login(conn, root);
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
}
