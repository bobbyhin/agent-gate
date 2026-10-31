// Made-up personal numbers for the leak guard's PII rules, built at run time from pieces, with their
// check digits computed here. No complete number appears in the source, and none of them belongs to
// anyone: they only have the shape and the checksum of the real kinds, so that the rules can be tested.
import { luhnCheckDigit, myNumberCheckDigit } from "../../src/llm/validators.js";

const withLuhn = (body: string): string => `${body}${luhnCheckDigit(body)}`;
const withMyNumberDigit = (first11: string): string => `${first11}${myNumberCheckDigit(first11)}`;
/** The same digits with the last one changed, so that its check fails. */
const broken = (digits: string): string => `${digits.slice(0, -1)}${(Number(digits.slice(-1)) + 1) % 10}`;
const groups = (digits: string, sizes: number[], separator: string): string => {
  const out: string[] = [];
  let at = 0;
  for (const size of sizes) {
    out.push(digits.slice(at, at + size));
    at += size;
  }
  return out.join(separator);
};

const card = withLuhn(["4", "12".repeat(7)].join(""));
const myNumber = withMyNumberDigit(["3", "21".repeat(5)].join(""));

export const PII = {
  /** 16 digits that pass the Luhn check, run together. */
  card,
  /** The same, in groups of four. */
  cardSpaced: groups(card, [4, 4, 4, 4], " "),
  cardDashed: groups(card, [4, 4, 4, 4], "-"),
  /** The same digits with a wrong check digit: shaped like a card, but not one. */
  cardBadCheck: groups(broken(card), [4, 4, 4, 4], " "),
  /** 12 digits whose last one is the My Number check digit. */
  myNumber,
  myNumberSpaced: groups(myNumber, [4, 4, 4], " "),
  myNumberBadCheck: broken(myNumber),
  /** In the ranges the SSA assigns. */
  ssn: [String(200 + 17), ["4", "1"].join(""), ["5", "00", "8"].join("")].join("-"),
  /** Shaped like an SSN, in ranges the SSA never assigns. */
  ssnArea666: ["6".repeat(3), ["4", "1"].join(""), ["5", "00", "8"].join("")].join("-"),
  ssnGroup00: [String(200 + 17), "0".repeat(2), ["5", "00", "8"].join("")].join("-"),
  /** 9 first, 74 in the middle: an ITIN's ranges. */
  itin: [["9", "12"].join(""), ["7", "4"].join(""), ["3", "00", "6"].join("")].join("-"),
  /** 89 in the middle: reserved, never an ITIN. */
  itinGroup89: [["9", "12"].join(""), ["8", "9"].join(""), ["3", "00", "6"].join("")].join("-"),
} as const;
