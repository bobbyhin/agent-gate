// Checks that a number a leak-guard rule found is really of its kind, not only shaped like it: a rule
// with "validator" counts a match only when the validator accepts it. Each one looks at the digits of
// the match and nothing else. All are pure.
//
//   luhn          a payment card number: 13 to 19 digits whose Luhn checksum is 0 (ISO/IEC 7812-1)
//   jp-my-number  a Japanese Individual Number (My Number): 12 digits, the last of which is the check
//                 digit that the Ministry of Internal Affairs and Communications defines: 11 minus
//                 (the sum of Pn x Qn for n = 1..11, modulo 11), or 0 when that remainder is 0 or 1,
//                 where Pn is the n-th digit counted from the right of the other 11 and Qn is n + 1 for
//                 n <= 6 and n - 5 for n >= 7. Ordinance of the Ministry of Internal Affairs and
//                 Communications No. 85 of 2014, article 5: https://laws.e-gov.go.jp/law/426M60000008085
//   us-ssn        a US Social Security number the SSA could have assigned: never 000, 666 or 900-999
//                 first, 00 in the middle or 0000 last (SSA POMS RM 10201.035,
//                 https://secure.ssa.gov/poms.nsf/lnx/0110201035)
//   us-itin       a US Individual Taxpayer Identification Number: 9 first, and 50-65, 70-88, 90-92 or
//                 94-99 as the fourth and fifth digits (IRS IRM 3.21.263.2,
//                 https://www.irs.gov/irm/part3/irm_03-021-263r)

export type ValidatorName = "luhn" | "jp-my-number" | "us-ssn" | "us-itin";

const digitsOf = (text: string): string => text.replace(/\D/g, "");

/** The Luhn sum of a digit string is a multiple of 10. */
export function luhnValid(digits: string): boolean {
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = digits.charCodeAt(digits.length - 1 - i) - 48;
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return digits.length > 0 && sum % 10 === 0;
}

/** The digit that makes `digits` followed by it pass the Luhn check. */
export function luhnCheckDigit(digits: string): number {
  for (let d = 0; d <= 9; d++) if (luhnValid(`${digits}${d}`)) return d;
  throw new Error("unreachable: one of ten digits always completes a Luhn sum");
}

/** The My Number check digit of the first 11 digits. */
export function myNumberCheckDigit(first11: string): number {
  if (!/^\d{11}$/.test(first11)) throw new Error("a My Number check digit needs exactly 11 digits");
  let sum = 0;
  for (let n = 1; n <= 11; n++) sum += Number(first11[11 - n]) * (n <= 6 ? n + 1 : n - 5);
  const remainder = sum % 11;
  return remainder <= 1 ? 0 : 11 - remainder;
}

export const VALIDATORS: Readonly<Record<ValidatorName, (match: string) => boolean>> = {
  luhn: (match) => {
    const digits = digitsOf(match);
    return digits.length >= 13 && digits.length <= 19 && luhnValid(digits);
  },
  "jp-my-number": (match) => {
    const digits = digitsOf(match);
    return digits.length === 12 && myNumberCheckDigit(digits.slice(0, 11)) === Number(digits[11]);
  },
  "us-ssn": (match) => {
    const digits = digitsOf(match);
    if (digits.length !== 9) return false;
    const [area, group, serial] = [digits.slice(0, 3), digits.slice(3, 5), digits.slice(5)];
    return area !== "000" && area !== "666" && !area.startsWith("9") && group !== "00" && serial !== "0000";
  },
  "us-itin": (match) => {
    const digits = digitsOf(match);
    if (digits.length !== 9 || !digits.startsWith("9")) return false;
    const group = Number(digits.slice(3, 5));
    return (group >= 50 && group <= 65) || (group >= 70 && group <= 88) || (group >= 90 && group <= 92) || (group >= 94 && group <= 99);
  },
};

export const VALIDATOR_NAMES = Object.keys(VALIDATORS) as ValidatorName[];
