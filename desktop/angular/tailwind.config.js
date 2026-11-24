const plugin = require("tailwindcss/plugin");

// A theme color as an RGB variable, so that opacity utilities work.
const v = (name) => `rgb(var(--pm-${name}) / <alpha-value>)`;

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
      background: v("bg"),

      // Theme colors, see src/theme/_appearance.scss.
      gray: {
        100: v("gray-100"),
        200: v("gray-200"),
        300: v("gray-300"),
        400: v("gray-400"),
        500: v("gray-500"),
        600: v("gray-600"),
        700: v("gray-700"),
        DEFAULT: v("gray-700"),
      },

      green: {
        100: v("green-100"),
        200: v("green-200"),
        300: v("green-300"),
        DEFAULT: v("green-200"),
      },

      red: {
        100: v("red-100"),
        200: v("red-200"),
        300: v("red-300"),
        DEFAULT: v("red"),
      },

      yellow: {
        100: v("yellow-100"),
        200: v("yellow-200"),
        300: v("yellow-300"),
        DEFAULT: v("yellow-300"),
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

      // The accent color, chosen in the appearance settings.
      blue: {
        DEFAULT: v("accent"),
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
        primary: v("text-1"),
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
      // Corners follow the theme and the appearance settings.
      borderRadius: {
        sm: "var(--pm-radius-sm)",
        DEFAULT: "var(--pm-radius)",
        md: "var(--pm-radius-md)",
        lg: "var(--pm-radius-lg)",
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
