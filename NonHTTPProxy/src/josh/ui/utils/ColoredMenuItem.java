package josh.ui.utils;

import java.awt.Color;
import java.awt.Graphics;

import javax.swing.JMenuItem;

public class ColoredMenuItem extends JMenuItem {

    private Color backgroundColor;

    public ColoredMenuItem(String text, Color backgroundColor) {
        super(text);
        this.backgroundColor = backgroundColor;
    }

    @Override
    protected void paintComponent(Graphics g) {
        // Set the custom background color before painting the JMenuItem
        g.setColor(backgroundColor);
        g.fillRect(0, 0, getWidth(), getHeight());

        // Call the parent class's paintComponent to ensure default rendering
        super.paintComponent(g);
    }

    public Color getBackgroundColor() {
        return backgroundColor;
    }

    public void setBackgroundColor(Color backgroundColor) {
        this.backgroundColor = backgroundColor;
    }
}
    
