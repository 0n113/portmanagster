const plugin = require("tailwindcss/plugin");

module.exports = {
  content: [
    "./src/**/*.{html,scss,css,ts}",
    "./projects/**/*.{html,scss,css,ts}",
  ],
  theme: {
    colors: {
      transparent: "transparent",
      current: "currentColor",
      white: "#ffffff",
      background: "#1a1a1d",

      gray: {
        100: "#151517",
        200: "#1d1d20",
        300: "#252528",
        400: "#2c2c2f",
        500: "#48484c",
        600: "#8e8e93",
        700: "#a1a1a6",
        DEFAULT: "#a1a1a6",
      },

      green: {
        100: "#0f3a1d",
        200: "#248a3d",
        300: "#30d158",
        DEFAULT: "#248a3d",
      },

      red: {
        100: "#3d1715",
        200: "#a3261e",
        300: "#ff453a",
        DEFAULT: "#ff453a",
      },

      yellow: {
        100: "#3d3508",
        200: "#a68b06",
        300: "#ffd60a",
        DEFAULT: "#ffd60a",
      },

      cyan: {
        100: "#b2ebf2",
        200: "#80deea",
        300: "#4dd0e1",
        400: "#26c6da",
        500: "#00bcd4",
        600: "#00acc1",
        700: "#0097a7",
        800: "#00838f",
        900: "#006064",
      },

      deepPurple: {
        50: "#ede7f6",
        100: "#d1c4e9",
        200: "#b39ddb",
        300: "#9575cd",
        400: "#7e57c2",
        500: "#673ab7",
        600: "#5e35b1",
        700: "#512da8",
        800: "#4527a0",
        900: "#311b92",
      },

      blue: {
        DEFAULT: "#0a84ff",
      },

      // Legacy color definitions

      // The overall application background color

      // Text shades
      cards: {
        primary: "var(--cards-primary)",
        secondary: "var(--cards-secondary)",
        tertiary: "var(--cards-tertiary)",
      },

      buttons: {
        icon: "var(--button-icon)",
        dark: "var(--button-dark)",
        light: "var(--button-light)",
      },

      info: {
        green: "var(--info-green)",
        red: "var(--info-red)",
        gray: "var(--info-gray)",
        blue: "var(--info-blue)",
        yellow: "var(--info-yellow)",
      },
    },
    textColor: (theme) => {
      return {
        primary: "#ededee",
        secondary: theme("colors.gray.700"),
        tertiary: theme("colors.gray.600"),

        ...theme("colors"),
      };
    },
    extend: {
      boxShadow: {
        xs: "0 0 0 1px rgba(0, 0, 0, 0.05)",
        "inner-xs": "inset 0 2px 4px 0 rgba(0, 0, 0, 0.16)",
      },
      fontSize: {
        xxs: "0.7rem",
      },
      // Rounder corners, as in the macOS (WhiteSur) theme.
      borderRadius: {
        sm: "5px",
        DEFAULT: "7px",
        md: "8px",
        lg: "10px",
      },
    },
  },
  plugins: [
    plugin(function ({ addVariant, theme }) {
      Object.keys(theme("screens")).forEach((key) => {
        addVariant("sfng-" + key, ".min-width-" + theme("screens")[key] + " &");
      });
    }),
  ],
};
