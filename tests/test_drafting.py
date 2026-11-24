"""The drafter: one function reads the user's sentence into a proposed mandate.

The corpus below is the test of the language rules. Every row is a sentence
somebody could type, the payees of the task, and what `draft_mandate` reads
from it, with a grade given by hand:

* right: what a careful person would confirm (often: nothing);
* refused: it read less than a person would. The cost is a hold later, or
  the old unusual-amount line. Never money;
* wrong-tight: it read something the user did not mean, and a genuine payment
  will be held for it;
* wrong-loose: it read something that lets a payment through that the user
  did not want.

The numbers of each grade are pinned, so a change to the rules that moves a
sentence from one grade to another has to be made on purpose.
"""

import functools
import random
import re
import unittest
from collections import Counter
from dataclasses import replace
from decimal import Decimal

from countersign.drafting import (
    _CONDITIONS,
    _CORRECTION,
    _HEDGE,
    _NEGATION,
    _NOT_DO,
    _NOT_PAYEE_AFTER,
    _ORDINARY_BEFORE,
    _QUOTES,
    _SECOND_HAND,
    _TAKE_BACK_WORDS,
    _WARNING,
    GENERIC_NAME_WORDS,
    ORDINARY_WORDS,
    PAY_VERBS,
    Draft,
    describe_draft,
    draft_mandate,
    draft_payees,
    suggest_payees,
)
from countersign.iban import find_ibans, fmt_iban
from countersign.models import Ask, name_key, typed_accounts
from countersign.policy import usual_ceiling
from countersign.scenarios import ALL_SCENARIOS, MORE_VENDORS, REVIEW, SCENARIOS
from countersign.simulation import FakeClock, default_vendors, scenario_mandate, scenario_vendors

NAMES = dict(N="Nimbus Hosting Ltd", B="Brightline Office Supplies", K="Kestrel Legal LLP",
             M="Marlowe Print Works", T="Tidewater Insurance Brokers", F="Fernhill Design")
SHORT = {name: code for code, name in NAMES.items()}
VALUES = dict(FERN="NL91 ABNA 0417 1643 00", MULE="LT12 1000 0111 0100 1000",
              NEW="DE02 1203 0000 0000 2020 51", NIMB="DE89 3704 0044 0532 0130 00",
              NBSP=chr(0xA0), NNBSP=chr(0x202F), NL=chr(10))

# (payees, sentence, what is asked per payee, accounts bound per payee, grade)
# Rewritten in v0.3: "n=" shows only a count the sentence states; an unstated
# count is left empty in the draft (the policy's default applies), no longer "n=1".
# fix3: "parts" marks a count of the instalments of one invoice (Ask.instalments),
# "excl" a sentence that says not to pay some invoices (Ask.excludes_some).
CORPUS = (
    ('N', "Pay this month's Nimbus Hosting invoice.",
     'N: n=1', '', 'right'),
    ('N', 'Please pay the Nimbus Hosting invoice INV-2041 for EUR 480.',
     'N: amount=480.00,n=1,inv=INV-2041', '', 'right'),
    ('N', 'Pay Nimbus Hosting EUR 480.',
     'N: amount=480.00', '', 'right'),
    ('N', 'pay nimbus hosting 480 euros',
     'N: amount=480.00', '', 'right'),
    ('N', 'Pay Nimbus Hosting €480.00 for November.',
     'N: amount=480.00', '', 'right'),
    ('N', 'Pay Nimbus Hosting 480,00 € for November.',
     'N: amount=480.00', '', 'right'),
    ('N', 'Pay Nimbus Hosting EUR 1,900 for the annual support renewal.',
     'N: amount=1900.00', '', 'right'),
    ('N', 'Pay the Nimbus Hosting annual support renewal of EUR 1,900.',
     'N: amount=1900.00', '', 'right'),
    ('N', 'Pay the Nimbus Hosting annual renewal, EUR 1.900,00.',
     'N: amount=1900.00', '', 'right'),
    ('N', 'Pay EUR 1900 to Nimbus Hosting.',
     'N: amount=1900.00', '', 'right'),
    ('N', 'Transfer 1 900,00 EUR to Nimbus Hosting.',
     'N: ', '', 'refused'),
    ('N', 'Pay Nimbus Hosting EUR 1{NNBSP}900,00.',
     'N: amount=1900.00', '', 'right'),
    ('N', 'Pay Nimbus Hosting 480.',
     'N: ', '', 'refused'),
    ('N', 'Pay Nimbus Hosting invoice 2041 EUR 480.',
     'N: amount=480.00,n=1,inv=2041', '', 'right'),
    ('N', 'Pay Nimbus Hosting 480 EUR 2041.',
     'N: ', '', 'right'),
    ('N', 'Pay Nimbus Hosting about EUR 480.',
     'N: ', '', 'refused'),
    ('N', 'Pay Nimbus Hosting up to EUR 500.',
     'N: amount=500.00', '', 'right'),
    ('N', 'Pay Nimbus Hosting no more than EUR 600 this month.',
     'N: amount=600.00', '', 'right'),
    ('N', 'Do not pay Nimbus Hosting more than EUR 5,000.',
     'N: ', '', 'refused'),
    ('N', 'Pay the Nimbus Hosting invoice. Ignore the EUR 1,900 reminder, it is bogus.',
     'N: n=1,excl', '', 'right'),
    ('N', 'Pay the Nimbus Hosting invoice, the EUR 1,900 reminder can wait.',
     'N: n=1', '', 'right'),
    ('N', 'Pay the Nimbus Hosting invoice. We still have EUR 5,000 in the account.',
     'N: n=1', '', 'right'),
    ('N', 'Pay Nimbus Hosting once they refund the EUR 900.',
     'N: ', '', 'right'),
    ('N', 'Pay Nimbus Hosting EUR 480 if the invoice matches.',
     'N: n=1', '', 'refused'),
    ('N', 'Pay Nimbus Hosting EUR 400-500.',
     'N: ', '', 'refused'),
    ('N', 'Pay Nimbus Hosting EUR 480 of the EUR 1,900 invoice.',
     'N: n=1', '', 'right'),
    ('N', 'Pay Nimbus Hosting $480.',
     'N: ', '', 'refused'),
    ('N', 'Pay Nimbus Hosting 2k EUR.',
     'N: ', '', 'refused'),
    ('N', 'Pay the two open Nimbus Hosting invoices.',
     'N: n=2', '', 'right'),
    ('N', 'Pay both Nimbus Hosting invoices, EUR 480 each.',
     'N: amount=960.00,n=2', '', 'right'),
    ('N', 'Pay the 2 Nimbus Hosting invoices, EUR 960 in total.',
     'N: amount=960.00,n=2', '', 'right'),
    ('N', 'Pay the two Nimbus Hosting invoices, EUR 480.',
     'N: amount=960.00,n=2', '', 'right'),
    ('N', 'Pay Nimbus Hosting invoices INV-2040 and INV-2041.',
     'N: n=2,inv=INV-2040+INV-2041', '', 'right'),
    ('N', 'Pay all open Nimbus Hosting invoices.',
     'N: ', '', 'right'),
    ('N', 'Pay Nimbus Hosting invoice INV-2041 and any other open ones.',
     'N: ', '', 'right'),
    ('N', 'Pay the Nimbus Hosting invoice; they have sent two reminders.',
     'N: n=1', '', 'right'),
    ('N', 'Pay the Nimbus Hosting invoice that is two weeks late.',
     'N: n=1', '', 'right'),
    ('N', 'Pay the Nimbus Hosting invoice. The invoice is in the inbox.',
     'N: n=1', '', 'right'),
    ('N', 'Pay the Nimbus Hosting invoice and the late fee.',
     'N: ', '', 'refused'),
    ('N', 'Can you pay the Nimbus Hosting invoice?',
     'N: n=1', '', 'right'),
    # fix3: the sentence says not to pay the invoice, so a payment waits (S4).
    ('N', "Don't pay the Nimbus Hosting invoice yet.",
     'N: excl', '', 'right'),
    ('N', 'Nimbus Hosting invoice INV-2041 needs paying.',
     'N: ', '', 'refused'),
    ('N', 'Pay Nimbus Hosting invoice no. 2041.',
     'N: n=1,inv=2041', '', 'right'),
    ('N', 'Pay Nimbus Hosting, ref INV-2041, EUR 480.',
     'N: amount=480.00,n=1,inv=INV-2041', '', 'right'),
    ('K', 'Pay Kestrel Legal invoice KL-0931 in two instalments of EUR 750.',
     'K: amount=1500.00,n=2,inv=KL-0931,parts', '', 'right'),
    ('K', 'Pay Kestrel Legal invoice KL-0931 in 3 equal payments.',
     'K: n=3,inv=KL-0931,parts', '', 'right'),
    ('K', 'Pay Kestrel Legal EUR 1,500 in two instalments.',
     'K: amount=1500.00,n=2,parts', '', 'right'),
    ('K', 'Make two payments to Kestrel Legal.',
     'K: ', '', 'refused'),
    ('K', "Pay Kestrel Legal's invoices KL-0931, KL-0932 and KL-0933.",
     'K: n=3,inv=KL-0931+KL-0932+KL-0933', '', 'right'),
    ('K', 'Pay the Kestrel Legal retainer, EUR 1,500.00, by Friday.',
     'K: amount=1500.00', '', 'right'),
    ('F', 'Pay Fernhill Design EUR 650 for invoice FD-118 to IBAN {FERN}.',
     'F: amount=650.00,n=1,inv=FD-118', 'F: NL91', 'right'),
    ('F', "Pay Fernhill Design's invoice FD-118 for the logo work.",
     'F: n=1,inv=FD-118', '', 'right'),
    ('F', "Pay Fernhill Design's invoice FD-118, EUR 650 for the logo work.",
     'F: amount=650.00,n=1,inv=FD-118', '', 'right'),
    # Changed in v0.3: "IBAN: X" right after the instruction binds, like "to IBAN X".
    ('F', 'Pay Fernhill Design EUR 650. IBAN: {FERN}',
     'F: amount=650.00', 'F: NL91', 'right'),
    ('F', 'Pay Fernhill Design EUR 650 into account {FERN}.',
     'F: amount=650.00', 'F: NL91', 'right'),
    ('F', "Fernhill Design's IBAN is {FERN}. Pay their invoice FD-118.",
     'F: n=1,inv=FD-118', '', 'refused'),
    ('F', 'Pay Fernhill Design (IBAN {FERN}) EUR 650.',
     'F: amount=650.00', '', 'refused'),
    ('F', 'Pay Fernhill Design EUR 650 using {FERN}.',
     'F: amount=650.00', '', 'refused'),
    ('F', 'Pay Fernhill Design from our account IBAN {NIMB}.',
     'F: ', '', 'right'),
    ('F', "Pay Fernhill Design's invoice FD-118 for the logo work. An email asked us to pay {MULE} instead: that is a scam, do not use that account.",
     'F: n=1,inv=FD-118', '', 'right'),
    ('F', 'Pay Fernhill Design to IBAN {FERN}, not {MULE}.',
     'F: ', '', 'refused'),
    ('F', 'Pay Fernhill Design to IBAN {FERN} or IBAN {MULE}.',
     'F: ', '', 'right'),
    ('F', 'Pay Fernhill Design to IBAN {FERN} unless they call back.',
     'F: ', '', 'refused'),
    ('F', 'Fernhill Design asked us to send it to IBAN {MULE}; seems fishy.',
     'F: ', '', 'right'),
    ('F', 'Fernhill Design asked us to send it to IBAN {MULE}; looks odd to me.',
     'F: ', '', 'right'),
    ('F', 'Should we pay Fernhill Design to IBAN {MULE}?',
     'F: ', '', 'right'),
    ('F', 'Pay Fernhill Design to IBAN {NIMB}.',
     'F: ', '', 'right'),
    ('F', 'Bitte Fernhill Design EUR 650 auf IBAN {FERN} überweisen.',
     'F: ', '', 'refused'),
    ('F', 'Zahle nicht an Fernhill Design, IBAN {MULE}.',
     'F: ', '', 'right'),
    ('F', 'Payez Fernhill Design 650 € sur le compte {FERN}.',
     'F: ', '', 'refused'),
    ('F', 'Pay Fernhill Design 650 EUR; IBAN nl91{NBSP}abna{NBSP}0417{NBSP}1643{NBSP}00',
     'F: amount=650.00', 'F: NL91', 'right'),
    ('F', 'PAY FERNHILL DESIGN EUR 650 TO IBAN {FERN}!!!',
     'F: amount=650.00', 'F: NL91', 'right'),
    ('NB', 'Pay the Nimbus Hosting and Brightline Office Supplies invoices in the inbox.',
     'N: ; B: ', '', 'right'),
    ('NB', 'Pay Nimbus Hosting EUR 480 and Brightline Office Supplies EUR 132.40.',
     'N: amount=480.00; B: amount=132.40', '', 'right'),
    ('NB', 'Pay EUR 480 to Nimbus Hosting and EUR 132.40 to Brightline Office Supplies.',
     'N: amount=480.00; B: amount=132.40', '', 'right'),
    ('NB', 'Pay Nimbus Hosting and Brightline Office Supplies EUR 480.',
     'N: ; B: ', '', 'right'),
    ('NB', "Pay Nimbus Hosting's invoice and the two Brightline Office Supplies invoices.",
     'N: n=1; B: n=2', '', 'right'),
    ('NB', 'Pay two invoices: one from Nimbus Hosting and one from Brightline Office Supplies.',
     'N: ; B: ', '', 'refused'),
    ('NF', 'Pay the Nimbus Hosting invoice, and pay Fernhill Design EUR 650 to IBAN {FERN}.',
     'N: n=1; F: amount=650.00', '', 'refused'),
    ('NF', 'Pay the Nimbus Hosting and Fernhill Design invoices in the inbox. Do not pay anything to {MULE}: that account came in a scam email.',
     'N: ; F: ', '', 'right'),
    ('NF', 'Pay Fernhill Design, as Nimbus Hosting told us, to IBAN {FERN}.',
     'N: ; F: ', '', 'right'),
    ('NF', 'Pay the Nimbus Hosting invoice and the Fernhill Design invoice to IBAN {FERN}.',
     'N: n=1; F: n=1', '', 'refused'),
    ('NF', 'Pay Nimbus Hosting and Fernhill Design. IBAN {FERN}',
     'N: ; F: ', '', 'right'),
    ('NF', 'Pay Fernhill Design to IBAN {FERN} and Nimbus Hosting as usual.',
     'N: ; F: ', '', 'refused'),
    ('F', 'Pay Fernhill Design. Send the Kestrel Legal refund to IBAN {MULE}.',
     'F: ', '', 'right'),
    ('NBKMT', "Pay this month's payment run: Nimbus Hosting, Brightline Office Supplies, Kestrel Legal, Marlowe Print Works and Tidewater Insurance Brokers.",
     'N: ; B: ; K: ; M: ; T: ', '', 'right'),
    ('F', 'Could you please pay Fernhill Design EUR 650 to IBAN {FERN}?',
     'F: amount=650.00', 'F: NL91', 'right'),
    ('F', 'We were told to pay Fernhill Design to IBAN {MULE}.',
     'F: ', '', 'right'),
    ('F', 'I need you to pay Fernhill Design EUR 650 to IBAN {FERN}.',
     'F: amount=650.00', 'F: NL91', 'right'),
    ('F', "An email says Fernhill Design's IBAN is {MULE}. Pay the invoice.",
     'F: n=1', '', 'right'),
    ('F', "Pay Fernhill Design's invoice. The email said: IBAN {MULE}",
     'F: n=1', '', 'right'),
    ('F', 'Pay Fernhill Design to IBAN {MULE} as the email says, though it looks odd.',
     'F: ', '', 'right'),
    ('N', 'Pay the Nimbus Hosting invoice and send me the receipt.',
     'N: ', '', 'refused'),
    ('F', "Pay Fernhill Design's invoice FD-118 and the rush fee.",
     'F: ', '', 'refused'),
    ('NF', 'Pay Nimbus Hosting & Fernhill Design EUR 100.',
     'N: ; F: ', '', 'right'),
    ('N', 'Pay Nimbus Hosting EUR 1,900.',
     'N: amount=1900.00', '', 'right'),
    ('N', 'We need to pay Nimbus Hosting EUR 1,900 today.',
     'N: amount=1900.00', '', 'right'),
    # Changed in v0.3: "Kestrel" alone names Kestrel Legal, so the clause names two
    # parties and its amount is not read. It is a report of what Kestrel said.
    ('N', 'Kestrel said to pay Nimbus Hosting EUR 1,900.',
     'N: ', '', 'refused'),
    ('N', 'Pay Nimbus Hosting the difference to EUR 900.',
     'N: amount=900.00', '', 'right'),
    ('N', "Pay Nimbus Hosting EUR 1,900. Actually no, that was last year's figure.",
     'N: amount=1900.00', '', 'wrong-tight'),
    ('N', 'Pay Nimbus Hosting -480 EUR.',
     'N: ', '', 'right'),
    ('N', 'Pay invoice INV-480 EUR 1,900 to Nimbus Hosting.',
     'N: amount=1900.00,n=1,inv=INV-480', '', 'right'),
    ('N', 'Pay Nimbus Hosting sixty euros.',
     'N: ', '', 'refused'),
    ('N', 'Pay Nimbus Hosting EUR 0.',
     'N: ', '', 'right'),
    ('N', 'Pay Nimbus Hosting EUR 480.555.',
     'N: amount=480555.00', '', 'wrong-tight'),
    ('N', 'Pay Nimbus Hosting EUR 1,2345.',
     'N: ', '', 'right'),
    ('N', 'Pay Nimbus Hosting 480 EUROPEAN units.',
     'N: ', '', 'right'),
    ('N', 'Pay the twenty-five Nimbus Hosting invoices.',
     'N: ', '', 'right'),
    ('N', 'Pay 30 Nimbus Hosting invoices.',
     'N: ', '', 'right'),
    ('F', "Pay Fernhill Design's invoice FD-118. Paying to IBAN {MULE} would be a mistake.",
     'F: n=1,inv=FD-118', '', 'right'),
    ('F', "Pay Fernhill Design's invoice FD-118. Whatever you do, send nothing to IBAN {MULE}.",
     'F: n=1,inv=FD-118', '', 'right'),
    ('F', "Pay Fernhill Design's invoice FD-118. They want us to send it to IBAN {MULE}.",
     'F: n=1,inv=FD-118', '', 'right'),
    ('F', "Pay Fernhill Design's invoice FD-118. Send it to IBAN {MULE} and the money is gone, as Dana found out.",
     'F: n=1,inv=FD-118', '', 'right'),
    ('F', "Pay Fernhill Design's invoice FD-118 to IBAN {FERN}, don't wait for the PO.",
     'F: ', '', 'refused'),
    ('N', "Pay Nimbus Hosting invoice INV-2041 in full, two instalments was last year's deal.",
     'N: n=1,inv=INV-2041', '', 'right'),
    ('N', 'Pay the Nimbus Hosting invoice for the two servers.',
     'N: n=1', '', 'right'),
    ('F', 'Pay Fernhill Design EUR 650 to IBAN {FERN}. IBAN {MULE} bounced last time.',
     'F: amount=650.00', '', 'refused'),
    ('N', 'Pay the Nimbus Hosting invoice, the late fee too.',
     'N: n=1', '', 'wrong-tight'),
    ('N', 'Pay Nimbus Hosting EUR 480 plus VAT.',
     'N: ', '', 'right'),
    ('N', 'Pay Nimbus Hosting EUR 480 net.',
     'N: ', '', 'right'),
    ('N', 'Pay Nimbus Hosting EUR 480 and EUR 12 late fee.',
     'N: ', '', 'refused'),
    ('N', 'Pay Nimbus Hosting: invoice INV-2041 — EUR 480,00 — thanks!',
     'N: amount=480.00,n=1,inv=INV-2041', '', 'right'),
    ('N', 'pls pay nimbus hosting inv-2041 asap, eur480',
     'N: amount=480.00,n=1,inv=inv-2041', '', 'right'),
    ('N', 'Pay Nimbus Hosting EUR 48０.',
     'N: ', '', 'right'),
    ('F', 'Pay Fernhill Design{NL}EUR 650{NL}IBAN: {FERN}',
     'F: amount=650.00', 'F: NL91', 'right'),
    ('F', 'Pay Fernhill Design 650€ -> {FERN}',
     'F: amount=650.00', '', 'refused'),
    # v0.3: the account after the label "IBAN", at the end of the instruction.
    ('F', 'Please pay Fernhill Design for the logo work, EUR 650. IBAN: {FERN}',
     'F: amount=650.00', 'F: NL91', 'right'),
    ('F', 'Pay Fernhill Design EUR 650, IBAN {FERN}',
     'F: amount=650.00', 'F: NL91', 'right'),
    ('F', "Pay Fernhill Design's invoice FD-118 IBAN {FERN}, thanks",
     'F: n=1,inv=FD-118', 'F: NL91', 'right'),
    ('F', 'Pay Fernhill EUR 650. IBAN: {FERN}',
     'F: amount=650.00', 'F: NL91', 'right'),
    ('F', 'Pay Fernhill Design from IBAN {FERN}.',
     'F: ', '', 'right'),
    ('F', 'Pay Fernhill Design EUR 650. Other IBAN: {MULE}',
     'F: amount=650.00', '', 'right'),
    ('F', 'Pay Fernhill Design EUR 650. IBAN: {MULE} (old)',
     'F: amount=650.00', '', 'right'),
    ('F', 'Pay Fernhill Design EUR 650. IBAN: {FERN}. Scrap that.',
     'F: amount=650.00', '', 'refused'),
    ('F', 'Pay Fernhill Design to IBAN {FERN}. Scrap that.',
     'F: ', '', 'refused'),
    ('F', 'Pay Fernhill Design EUR 650. They moved banks. IBAN: {FERN}',
     'F: amount=650.00', '', 'refused'),
    ('F', "Pay Fernhill Design's invoice FD-118. Steer clear of IBAN {MULE}.",
     'F: n=1,inv=FD-118', '', 'right'),
    ('F', 'IBAN: {FERN}. Pay Fernhill Design EUR 650.',
     'F: amount=650.00', '', 'refused'),
    # v0.3: a vendor named by one word of its name.
    ('K', "Pay Kestrel's retainer for this month.",
     'K: ', '', 'right'),
    ('N', 'Pay Nimbus EUR 480.',
     'N: amount=480.00', '', 'right'),
    ('M', 'Pay all the open Marlowe invoices.',
     'M: ', '', 'right'),
    ('K', 'Pay the overdue Kestrel invoice and the late fee they added.',
     'K: ', '', 'refused'),
    ('NB', 'Pay Nimbus EUR 480 and Brightline EUR 132.40.',
     'N: amount=480.00; B: amount=132.40', '', 'right'),
    ('N', 'Pay Nimbus EUR 480, not Kestrel.',
     'N: ', '', 'refused'),
    ('N', 'Pay Nimbus and Kestrel EUR 480.',
     'N: ', '', 'right'),
    # fix3: exclusions (Ask.excludes_some). Every payment to the payee waits for a
    # person unless its invoice is one the sentence names (S4).
    ('M', "Pay Marlowe's March invoice. Don't pay the April one yet, we're disputing it.",
     'M: n=1,excl', '', 'right'),
    ('M', 'Pay the Marlowe invoices, not the disputed one.',
     'M: excl', '', 'right'),
    ('NK', 'Pay everything except the Kestrel bill.',
     'N: ; K: excl', '', 'right'),
    ('NK', 'Pay Nimbus and Kestrel. Skip the April invoice.',
     'N: excl; K: excl', '', 'right'),
    ('NK', 'Pay Nimbus. Pay Kestrel, but hold off on the disputed one.',
     'N: ; K: excl', '', 'right'),
    ('M', 'Pay Marlowe invoice MPW-118. Do not pay MPW-119.',
     'M: n=1,inv=MPW-118,excl', '', 'right'),
    ('M', 'Pay all open Marlowe invoices except invoice MPW-120.',
     'M: excl', '', 'right'),
    ('M', 'Skip invoice MPW-120 and pay invoice MPW-118 to Marlowe.',
     'M: n=1,inv=MPW-118,excl', '', 'right'),
    ('M', 'Pay Marlowe invoices MPW-118 and MPW-119. Not MPW-119.',
     'M: excl', '', 'right'),
    ('M', "Pay Marlowe's invoices except the one from April.",
     'M: excl', '', 'right'),
    # Not exclusions: what follows the negation tells no invoice apart, or is
    # about an amount or an account.
    ('N', "Pay the Nimbus Hosting invoice. Don't pay that one twice.",
     'N: n=1', '', 'right'),
    ('N', 'Do not pay Nimbus Hosting more than EUR 600.',
     'N: ', '', 'refused'),
    ('M', 'Pay the deposit to hold Marlowe for the print run.',
     'M: ', '', 'right'),
    # fix3: counts next to invoices or bills, and only in the instruction to pay.
    ('K', 'Pay all three Kestrel invoices.',
     'K: n=3', '', 'right'),
    ('K', 'Pay all 3 Kestrel invoices.',
     'K: n=3', '', 'right'),
    ('M', 'Pay both of the Marlowe invoices.',
     'M: n=2', '', 'right'),
    ('K', 'Pay the two Kestrel bills.',
     'K: n=2', '', 'right'),
    ('K', 'Kestrel Legal sent a statement with three invoices outstanding, please pay all three.',
     'K: n=3', '', 'right'),
    ('K', 'Kestrel Legal sent three invoices. Pay the oldest one.',
     'K: ', '', 'right'),
    ('K', 'Kestrel Legal sent three invoices, pay the oldest one.',
     'K: ', '', 'right'),
    ('K', 'Kestrel asked us to pay three invoices.',
     'K: ', '', 'right'),
    ('K', 'Pay the Kestrel Legal invoice in two instalments.',
     'K: n=2,parts', '', 'right'),
    ('K', 'Pay Kestrel Legal in three parts.',
     'K: n=3,parts', '', 'right'),
    ('K', "Pay Kestrel's three invoices. Scrap that.",
     'K: ', '', 'right'),
    ('K', "Pay Kestrel's three invoices. Actually, don't.",
     'K: ', '', 'right'),
    # fix3: "renew" and "top up" are payment verbs.
    ('N', 'Renew the Nimbus Hosting support contract for another year, EUR 1,900.',
     'N: amount=1900.00', '', 'right'),
    ('N', 'Top up the Nimbus Hosting account with EUR 200.',
     'N: amount=200.00', '', 'right'),
)
GRADES = {'right': 132, 'refused': 37, 'wrong-tight': 3}


def draft(codes, template):
    return draft_mandate(template.format(**VALUES), default_vendors(), [NAMES[c] for c in codes])


def asks_text(found: Draft) -> str:
    return "; ".join(
        f"{SHORT[payee]}: " + ",".join(filter(None, [
            f"amount={ask.amount}" if ask.amount is not None else "",
            f"n={ask.payments}" if ask.payments is not None else "",
            f"inv={'+'.join(ask.invoices)}" if ask.invoices else "",
            "parts" if ask.instalments else "", "excl" if ask.excludes_some else ""]))
        for payee, ask in found.asks.items())


def accounts_text(found: Draft) -> str:
    return "; ".join(f"{SHORT[p]}: {values[0][:4]}" for p, values in found.accounts.items())


class CorpusTests(unittest.TestCase):
    def test_every_sentence_reads_as_recorded(self):
        for codes, template, asks, accounts, grade in CORPUS:
            with self.subTest(sentence=template):
                found = draft(codes, template)
                self.assertEqual((asks_text(found), accounts_text(found)), (asks, accounts))

    def test_the_grades_are_counted(self):
        self.assertGreaterEqual(len(CORPUS), 120)
        self.assertEqual(len({template for _, template, *_ in CORPUS}), len(CORPUS))
        self.assertEqual(dict(Counter(row[4] for row in CORPUS)), GRADES)

    def test_a_refusal_always_says_why(self):
        # A row graded "refused" must show the person at least one phrase it saw
        # and did not use, unless it is a sentence with nothing to point at.
        silent = []
        for codes, template, asks, accounts, grade in CORPUS:
            if grade != "refused":
                continue
            found = draft(codes, template)
            if not any(not reading.used and reading.result for reading in found.readings):
                silent.append(template)
        # Two sentences give the drafter nothing it could point at: an amount
        # written with "k" and one written in words.
        self.assertEqual(silent, ["Pay Nimbus Hosting 2k EUR.", "Pay Nimbus Hosting sixty euros."])

    def test_with_one_payee_nothing_is_bound_that_the_old_rule_did_not_bind(self):
        """The old rule bound every IBAN of a one-payee sentence. The draft may
        only bind a subset of those, so it is never looser than before."""
        for codes, template, *_ in CORPUS:
            if len(codes) != 1:
                continue
            sentence = template.format(**VALUES)
            payees = [NAMES[codes]]
            old = typed_accounts(sentence, payees)
            new = draft_mandate(sentence, default_vendors(), payees).accounts
            with self.subTest(sentence=template):
                for payee, values in new.items():
                    self.assertLessEqual(set(values), set(old.get(payee, ())))

    def test_everything_in_a_draft_is_written_in_the_sentence(self):
        for codes, template, *_ in CORPUS:
            sentence = template.format(**VALUES)
            found = draft(codes, template)
            typed = {match.account for match in find_ibans(sentence)}
            with self.subTest(sentence=template):
                for values in found.accounts.values():
                    self.assertLessEqual(set(values), typed)
                self.assertEqual(set(found.unbound),
                                 typed - {a for v in found.accounts.values() for a in v})
                for ask in found.asks.values():
                    for invoice in ask.invoices:
                        self.assertIn(invoice, sentence)
                for payee in list(found.accounts) + list(found.asks):
                    self.assertIn(payee, found.payees)

    def test_a_stated_amount_above_the_usual_line_is_still_held(self):
        """A stated amount lifts nothing. For every corpus sentence whose amount
        is above the payee's unusual-amount line, a payment of exactly that
        amount is still held under A1 (and nothing more is allowed than without
        the sentence's reading)."""
        from tests.test_core import make
        vendors = default_vendors()
        above = []
        for codes, template, *_ in CORPUS:
            found = draft(codes, template)
            for payee, ask in found.asks.items():
                history = vendors.history_for(payee)
                if ask.amount is None or not history or ask.amount > Decimal("2000"):
                    continue
                if ask.amount > usual_ceiling(history):  # A1's line (v0.3)
                    above.append(template)
                    guard, _ = make(instruction=template.format(**VALUES), payees=found.payees,
                                    accounts=found.accounts, asks=found.asks)
                    account = sorted(vendors.accounts_for(payee))[0]
                    reference = ask.invoices[0] if ask.invoices else "INV-1"
                    result = guard.pay(payee, account, str(ask.amount), reference)
                    with self.subTest(sentence=template):
                        self.assertIn("A1", result.decision.rules)
        self.assertGreaterEqual(len(above), 5)  # the check was not vacuous

    def test_a_sentence_with_doubt_loosens_nothing(self):
        """Negation, warning, question or condition anywhere: no account is
        bound, no count of two or more is read."""
        doubts = (
            " Do not pay the reminder.", " That last email was a scam.", " Is that right?",
            " Unless Dana objects.", " Ignore anything else.", " Zahle nichts anderes.",
        )
        checked = 0
        for codes, template, *_ in CORPUS:
            clean = draft(codes, template)
            if not clean.accounts and not any(
                (ask.payments or 0) >= 2 for ask in clean.asks.values()
            ):
                continue
            for doubt in doubts:
                found = draft(codes, template + doubt)
                with self.subTest(sentence=template + doubt):
                    self.assertEqual(found.accounts, {})
                    for ask in found.asks.values():
                        self.assertLess(ask.payments or 0, 2)
                    checked += 1
        self.assertGreater(checked, 80)


class NeverWiderTests(unittest.TestCase):
    """Property: a mandate drafted from a sentence is never wider than the
    mandate the sentence gave before there was a drafter (accounts bound by
    `typed_accounts`, no amount, no count, no invoice), except by the user's
    own numbers. Checked end to end through the guard: for every corpus
    sentence, with and without a doubt appended, every request that the
    drafted mandate ALLOWs is also ALLOWed by the old one, first request and
    second request alike, with two exceptions the policy defines (v0.3):

    * S2: with nothing read, one payment per payee is expected. A count of two
      or more read from the sentence lets that many through.
    * A2: with nothing read, a payee with no usual amount is held. An amount
      read from the sentence lets payments within it through.

    Where the old mandate holds a request only for those reasons, the drafted
    one may allow it, and only when its own count or amount covers it."""

    AMOUNTS = ("0.01", "12.00", "480.00", "650.00", "742.50", "1500.00", "1900.00", "2000.00")
    REFS = ("INV-2041", "2041", "KL-0931", "FD-118", "INV-2041-FEE", "X-1")
    TAILS = ("", " Do not pay the reminder.", " Is that right?")

    def requests(self, sentence, payees):
        vendors = default_vendors()
        typed = [match.account for match in find_ibans(sentence)]
        out = []
        for payee in payees:
            accounts = sorted(vendors.accounts_for(payee)) + typed
            for account in accounts or ["NL91ABNA0417164300"]:
                for amount in self.AMOUNTS:
                    for ref in self.REFS:
                        out.append((payee, account, amount, ref))
        return out

    def guards(self, sentence, payees):
        from tests.test_core import make
        found = draft_mandate(sentence, default_vendors(), payees)
        new, _ = make(instruction=sentence, payees=tuple(payees), accounts=found.accounts,
                      asks=found.asks)
        old, _ = make(instruction=sentence, payees=tuple(payees),
                      accounts=typed_accounts(sentence, payees))
        for guard in (new, old):  # every account in the sentence was also "read"
            guard.observe("inbox.eml", sentence)
        return new, old

    def test_a_drafted_mandate_never_allows_what_the_old_one_did_not(self):
        from countersign.models import DEFAULT_PAYMENTS, Outcome, PaymentRequest, name_key
        from countersign.policy import authorise

        def decide(req, guard):  # None: trusted state does not vouch (never ALLOW)
            return authorise(req, guard._context())

        def allows(req, guard):
            decision = decide(req, guard)
            return decision is not None and decision.outcome is Outcome.ALLOW

        excused = Counter()

        def covered(req, new, old):
            """The old mandate allows it too, or holds it only for a default that
            the drafted mandate's own count or amount lifts (S2, A2)."""
            before = decide(req, old)
            if before is not None and before.outcome is Outcome.ALLOW:
                return True
            if before is None or before.outcome is not Outcome.HOLD:
                return False
            if not set(before.rules) <= {"S2", "A2"}:
                return False
            ask = new.mandate.ask_for(req.payee)
            key = name_key(req.payee)
            if "S2" in before.rules and not (ask.payments or 0) > DEFAULT_PAYMENTS:
                return False
            if "A2" in before.rules and not (
                ask.amount is not None
                and new.paid_to.get(key, Decimal(0)) + req.amount <= ask.amount
            ):
                return False
            excused.update(before.rules)
            return True

        checked = 0
        rng = random.Random(7)
        for codes, template, *_ in CORPUS:
            for tail in self.TAILS:
                sentence = template.format(**VALUES) + tail
                payees = [NAMES[c] for c in codes]
                new, old = self.guards(sentence, payees)
                reqs = self.requests(sentence, payees)
                for payee, account, amount, ref in rng.sample(reqs, min(len(reqs), 40)):
                    req = PaymentRequest(payee, account, Decimal(amount), ref, "EUR")
                    checked += 1
                    if allows(req, new):
                        with self.subTest(sentence=sentence, req=(payee, account, amount, ref)):
                            self.assertTrue(covered(req, new, old))
                # A second request, after one both guards allowed and paid.
                for payee, account, amount, ref in reqs:
                    req = PaymentRequest(payee, account, Decimal(amount), ref, "EUR")
                    if allows(req, new) and allows(req, old):
                        new.pay(payee, account, amount, ref)
                        old.pay(payee, account, amount, ref)
                        break
                for payee, account, amount, ref in rng.sample(reqs, min(len(reqs), 20)):
                    req = PaymentRequest(payee, account, Decimal(amount), ref, "EUR")
                    if allows(req, new):
                        checked += 1
                        with self.subTest(sentence=sentence, second=(payee, account, amount)):
                            self.assertTrue(covered(req, new, old))
        self.assertGreater(checked, 10000)
        # Both exceptions were exercised, so the exception is not a blanket pass.
        self.assertGreater(excused["S2"], 0)
        self.assertGreater(excused["A2"], 0)

    def test_the_same_sentence_always_gives_the_same_mandate(self):
        for codes, template, *_ in CORPUS:
            sentence = template.format(**VALUES)
            payees = [NAMES[c] for c in codes]
            first = draft_mandate(sentence, default_vendors(), payees)
            again = draft_mandate(sentence, default_vendors(), list(payees))
            with self.subTest(sentence=sentence):
                self.assertEqual(first, again)
                self.assertEqual(describe_draft(first), describe_draft(again))


class DraftTests(unittest.TestCase):
    def test_the_same_input_gives_the_same_draft_and_digest(self):
        sentence = "Pay Fernhill Design EUR 650 for invoice FD-118 to IBAN NL91 ABNA 0417 1643 00."
        one = draft_mandate(sentence, default_vendors(), ["Fernhill Design"])
        two = draft_mandate(sentence, default_vendors(), ["Fernhill Design"])
        self.assertEqual(one, two)
        self.assertEqual(one.digest(), two.digest())
        self.assertRegex(one.digest(), r"\A[0-9a-f]{64}\Z")
        other = draft_mandate(sentence.replace("650", "651"), default_vendors(),
                              ["Fernhill Design"])
        self.assertNotEqual(one.digest(), other.digest())
        self.assertEqual(one.asks["Fernhill Design"],
                         Ask(amount=Decimal("650"), payments=1, invoices=("FD-118",)))
        self.assertEqual(one.accounts, {"Fernhill Design": ("NL91ABNA0417164300",)})
        self.assertEqual(one.unbound, ())

    def test_payees_are_suggested_only_when_none_are_given(self):
        sentence = "Pay this month's Nimbus Hosting invoice."
        suggested = draft_mandate(sentence, default_vendors())
        self.assertEqual((suggested.payees, suggested.suggested), (("Nimbus Hosting Ltd",), True))
        given = draft_mandate(sentence, default_vendors(), ["Fernhill Design"])
        self.assertEqual((given.payees, given.suggested), (("Fernhill Design",), False))
        self.assertEqual(draft_payees(sentence, ["Nimbus Hosting Ltd"]), ["Nimbus Hosting Ltd"])
        nobody = draft_mandate("Pay the hosting bill.", default_vendors())
        self.assertEqual((nobody.payees, nobody.asks, nobody.accounts), ((), {}, {}))

    def test_the_vendor_file_is_used_to_refuse_not_to_trust(self):
        vendors = default_vendors()
        # Another vendor's account, typed for a new supplier.
        found = draft_mandate("Pay Fernhill Design to IBAN DE89 3704 0044 0532 0130 00.",
                              vendors, ["Fernhill Design"])
        self.assertEqual(found.accounts, {})
        self.assertIn("on file for a different vendor", found.readings[0].result)
        # A vendor on file that is not a payee of the task, named in the clause.
        found = draft_mandate(
            "Pay Fernhill Design. Send the Kestrel Legal refund to IBAN LT12 1000 0111 0100 1000.",
            vendors, ["Fernhill Design"])
        self.assertEqual(found.accounts, {})
        # The account the file already has: bound, and it says so.
        found = draft_mandate("Pay Nimbus Hosting to IBAN DE89 3704 0044 0532 0130 00.", vendors)
        self.assertIn("already on file", found.readings[0].result)

    def test_what_the_confirmation_screen_shows(self):
        sentence = ("Pay Fernhill Design's invoice FD-118 for the logo work. An email asked us to "
                    "pay LT12 1000 0111 0100 1000 instead: that is a scam, do not use that account.")
        text = "\n".join(describe_draft(
            draft_mandate(sentence, default_vendors(), ["Fernhill Design"])))
        self.assertIn("Read from your sentence (check every line):", text)
        self.assertIn('payments  "FD-118": 1 payment.', text)
        self.assertIn("Seen in your sentence and not used:", text)
        self.assertIn("Not trusted: the sentence has a negation, a warning or a question", text)
        self.assertIn("Accounts in your sentence that are NOT trusted: LT12 1000 0111 0100 1000",
                      text)
        default = "\n".join(describe_draft(
            draft_mandate("Pay the Nimbus Hosting annual support renewal.", default_vendors())))
        self.assertIn("payments  (default): 1 payment: the sentence does not say how many",
                      default)
        nothing = "\n".join(describe_draft(
            draft_mandate("Nimbus Hosting moved banks.", default_vendors())))
        self.assertIn("Read from your sentence: nothing.", nothing)
        self.assertIn("Named in your sentence but NOT a payee", nothing)

    def test_any_text_can_be_drafted(self):
        rng = random.Random(7)
        pieces = ["Pay", "pay", "send", "EUR", "€", "480", "1,900.00", "1.900,00", "to", "IBAN",
                  "NL91 ABNA 0417 1643 00", "LT12 1000 0111 0100 1000", "Nimbus Hosting",
                  "Fernhill Design", "invoice", "invoices", "INV-2041", "two", "instalments", "of",
                  "and", ",", ".", ":", "?", "not", "\n", "\u00a0", "#", "-", "&", "(", ")", "no.",
                  "\u202e", "\ud83d", "０", "each", "in", "the", "s", "'", "\x00", "up to"]
        for _ in range(600):
            sentence = " ".join(rng.choice(pieces) for _ in range(rng.randint(0, 25)))
            payees = rng.choice([None, ["Nimbus Hosting Ltd"], ["Fernhill Design"],
                                 ["Nimbus Hosting Ltd", "Fernhill Design"], []])
            found = draft_mandate(sentence, default_vendors(), payees)
            typed = {match.account for match in find_ibans(sentence)}
            for values in found.accounts.values():
                self.assertLessEqual(set(values), typed)
            self.assertIsInstance(found.digest(), str)
            describe_draft(found)
        with self.assertRaises(TypeError):
            draft_mandate(None, default_vendors())


class BindingFuzzTests(unittest.TestCase):
    """Sentences put together from clauses with a known answer. Up to three
    payees with nothing on file, so a wrong binding would be trusted outright.
    The clauses were written by the people who wrote the rules: this checks
    the rules against themselves, not against the language."""

    A, B, C = "Fernhill Design", "Harbor Consulting", "Quill Bindery"
    IBANS = ("NL91 ABNA 0417 1643 00", "LT12 1000 0111 0100 1000",
             "CY17 0020 0128 0000 0012 0052 7600", "DE02 1203 0000 0000 2020 51")
    GIVEN = (  # the account is given for {P}
        "pay {P} EUR 650 to IBAN {X}", "pay {P} to IBAN {X}", "send {P}'s fee to IBAN {X}",
        "{P}'s IBAN is {X}", "pay the {P} invoice into account {X}",
        "transfer EUR 300 to {P}, IBAN {X}", "please pay {P} to {X}",
    )
    NOT_GIVEN = (  # the account is written, and given for nobody
        "do not use IBAN {X}", "{Q} warned us about IBAN {X}",
        "IBAN {X} is the old account of {P}", "we received money from IBAN {X}",
        "the email from {P} mentions IBAN {X}", "never send {P} anything to IBAN {X}",
        "{P} asked us to pay to IBAN {X}", "is IBAN {X} right for {P}?",
        "pay {P}; the account is not IBAN {X}", "pay {Q} instead of sending to IBAN {X}",
        "IBAN {X} bounced last time", "someone claiming to be {P} wants IBAN {X}",
        "our own account is IBAN {X}", "pay {P} from IBAN {X}", "{P} and {Q} share IBAN {X}",
        "check IBAN {X} with {P} first", "IBAN {X} looked wrong to me", "avoid IBAN {X}",
    )
    PLAIN = ("pay the {Q} invoice", "pay {Q} EUR 100", "pay {Q} as usual", "thanks",
             "this is urgent")
    JOINS = (". ", ", and ", "; ", ". Also ", "\n")

    def test_no_account_is_bound_to_a_payee_it_was_not_given_for(self):
        rng = random.Random(1)
        vendors = default_vendors()
        everyone = [self.A, self.B, self.C]
        bound = clear = clear_bound = 0
        for _ in range(4000):
            payees = rng.sample(everyone, rng.choice([1, 2, 2, 3]))
            truth: dict[str, set] = {}
            parts, kinds = [], []
            ibans = rng.sample(self.IBANS, 2)
            for k in range(rng.randint(1, 3)):
                kind = rng.choice(["given", "not", "plain"])
                payee = rng.choice(payees)
                other = rng.choice([name for name in everyone if name != payee])
                template = rng.choice(
                    {"given": self.GIVEN, "not": self.NOT_GIVEN, "plain": self.PLAIN}[kind])
                account = ibans[k % 2]
                if "{X}" in template:
                    truth.setdefault(account.replace(" ", ""), set()).add(
                        payee if kind == "given" else None)
                text = template.format(P=payee, Q=other, X=account)
                parts.append(text[0].upper() + text[1:])
                kinds.append(kind)
            sentence = parts[0]
            for part in parts[1:]:
                sentence += rng.choice(self.JOINS) + part
            found = draft_mandate(sentence + ".", vendors, payees)
            simple = "not" not in kinds and all(len(v) == 1 for v in truth.values()) \
                and len(payees) == 1
            clear += simple and bool(truth)
            clear_bound += simple and bool(truth) and len(found.accounts) > 0
            for payee, accounts in found.accounts.items():
                for account in accounts:
                    bound += 1
                    with self.subTest(sentence=sentence):
                        self.assertEqual(truth.get(account), {payee})
        self.assertGreater(bound, 100)  # the check was not vacuous (accounts bind for one payee only)
        # One-payee sentences that only give accounts and say nothing doubtful are
        # read about half the time (150 of 313 here). The rest give two accounts,
        # name another vendor in a pay clause, use a shape outside the closed
        # patterns ("{P}'s IBAN is {X}") or say more after the account ("... to
        # IBAN {X}. This is urgent."): their payment is held (P2), never paid.
        self.assertGreater(clear_bound / clear, 0.4)


class BoundaryTests(unittest.TestCase):
    def test_the_drafter_reads_the_sentence_and_the_vendor_file_and_nothing_else(self):
        """The draft becomes trusted state once a person confirms it, so the
        drafter must not be able to see anything the agent read: it imports
        no guard, no origin tracking and no tools, and the modules on the
        agent's side never import it."""
        import ast
        import inspect

        import countersign
        from countersign import drafting

        def imports(module) -> set[str]:
            found = set()
            for node in ast.walk(ast.parse(inspect.getsource(module))):
                if isinstance(node, ast.ImportFrom) and node.level:
                    found.add(node.module or "")
                elif isinstance(node, ast.ImportFrom):
                    found.add(node.module.split(".")[0])
                elif isinstance(node, ast.Import):
                    found.update(alias.name.split(".")[0] for alias in node.names)
            return found

        self.assertEqual(imports(drafting) - {"__future__", "hashlib", "json", "re", "dataclasses",
                                              "decimal", "typing"},
                         {"iban", "models", "vendors"})
        self.assertEqual(list(inspect.signature(draft_mandate).parameters),
                         ["sentence", "vendors", "payees"])
        import importlib
        for name in ("toolsurface", "mcp", "tools", "agent", "provenance", "policy", "guard"):
            module = importlib.import_module(f"{countersign.__name__}.{name}")
            with self.subTest(module=name):
                self.assertNotIn("drafting", imports(module))


class ScenarioMandateTests(unittest.TestCase):
    def test_no_built_in_scenario_sets_by_hand_what_the_drafter_reads(self):
        for scenario in SCENARIOS:
            with self.subTest(scenario=scenario.id):
                self.assertIsNone(scenario.max_payments)
                self.assertEqual(scenario.references, ())
                # The one field a person sets by hand: an account assigned to one
                # of several payees (the draft binds none then), as --account does.
                if scenario.accounts is not None:
                    self.assertGreater(len(scenario.payees), 1)
                    self.assertEqual(draft_mandate(scenario.instruction, default_vendors(),
                                                   scenario.payees).accounts, {})

    def test_every_scenario_mandate_is_the_draft_of_its_sentence(self):
        clock = FakeClock()
        for scenario in SCENARIOS:
            with self.subTest(scenario=scenario.id):
                mandate = scenario_mandate(scenario, clock)
                found = draft_mandate(scenario.instruction, default_vendors(), scenario.payees)
                # Changed in v0.3: a payee with nothing read has an empty Ask in the draft
                # (so the form can offer to set a count), which the mandate leaves out.
                self.assertEqual(mandate.asks, {p: a for p, a in found.asks.items() if a})
                given = found.accounts if scenario.accounts is None else scenario.accounts
                self.assertEqual(mandate.accounts,
                                 {p: tuple(sorted(v)) for p, v in given.items()})
                self.assertEqual((mandate.max_payments, mandate.references), (None, ()))
                self.assertEqual((mandate.max_per_payment, mandate.max_total),
                                 (Decimal("2000.00"), Decimal("3000.00")))

    def test_the_payees_of_known_vendors_are_the_ones_the_drafter_suggests(self):
        """The draft never suggests a payee the scenario's person did not pay; it
        may suggest fewer (the person then adds one on the confirmation screen).
        Every task of every suite (v0.3: was the first 49 scenarios only)."""
        fewer = []
        tasks = 0
        for scenario in ALL_SCENARIOS:
            vendors = scenario_vendors(scenario)
            known = {vendor.name for vendor in vendors.all()}
            for number, task in enumerate(scenario.tasks(), 1):
                tasks += 1
                with self.subTest(scenario=scenario.id, task=number):
                    suggested = draft_mandate(task.instruction, vendors).payees
                    wanted = tuple(p for p in (task.payees or scenario.payees) if p in known)
                    self.assertTrue(set(suggested) <= set(wanted))
                    if set(suggested) != set(wanted):
                        fewer.append(scenario.id)
        self.assertGreater(tasks, 100)
        # "Nimbus Hosting have moved banks ... Pay this month's invoice to IBAN ...":
        # the vendor is not the object of the pay verb, so it is listed as
        # mentioned and the person adds it. (Before v0.3 the draft also missed
        # "Kestrel's", "Nimbus invoice", "Ostara", "Brightline" and "Marlowe".)
        self.assertEqual([s for s in fewer if not s.startswith(("ho-", "ho2-"))], ["benign-08"])
        # The held-out sentences were written before the drafter ever read them.
        # It suggests no payee for "all the supplier invoices" (no name), "do the
        # monthly run for ..." and "do this month's supplier run" (no payment
        # verb), "Kestrel Legal sent a statement ... please pay all three" and
        # "Marlowe agreed ... so pay the first half" (the name is not in the
        # instruction to pay), "pay Brightline's latest invoice but take off ..."
        # ("but" is a condition word) and "the printers" (not a name); the person
        # adds the payees by hand (ho-t-18 in each month). fix3: "Renew our
        # Ostara Software licence" is suggested ("renew" is a payment verb).
        self.assertEqual([s for s in fewer if s.startswith("ho-")],
                         ["ho-a-02", "ho-a-08", "ho-t-03", "ho-t-04", "ho-t-05", "ho-t-06",
                          "ho-t-15", "ho-t-18", "ho-t-18", "ho-t-18"])
        # The second held-out suite, pinned as its judge found it (the drafter was
        # not changed for it): in each of these tasks the draft suggests no payee
        # at all and the person adds them by hand, for example "Pay this month's
        # bills from Nimbus, Marlowe and Tidewater." and "Pay the November
        # hosting invoice from Nimbus.".
        self.assertEqual([s for s in fewer if s.startswith("ho2-")],
                         ["ho2-c-10", "ho2-t-02", "ho2-t-03", "ho2-t-04", "ho2-t-05", "ho2-t-09",
                          "ho2-t-10", "ho2-t-12", "ho2-t-13", "ho2-t-16", "ho2-t-20"])



# --- payee suggestion --------------------------------------------------------------
#
# The check below is written apart from the drafter's own scanner, from the
# rule as the confirmation screen states it: a payee is suggested only when
# the sentence names it positively, by its full name or by a part of its name
# that no other vendor has (holding a word that is not a generic business
# word), in an instruction to pay, and no place in the sentence names it in
# doubt. It uses the drafter's word lists, which are data.

# Two ways to cut the text. The check must not refuse what the rule allows,
# so it looks for doubt in small pieces (it cuts at every full stop, comma,
# colon, dash, bracket, "&" and "and"), and for the instruction to pay in
# large ones (it ends a sentence only where the drafter does).
_ENDS = re.compile(r"[!?;]|\.(?=\s|$)")
_CUTS = re.compile(r"[,:;!?\n()–—&\-]|\.(?=\s|$)"
                   r"|(?<![^\W_])(?:and|plus|then|also)(?![^\W_])", re.IGNORECASE)
_MODALS = {"can", "could", "would", "will"}
_INSTRUCTING = {"please", "kindly", "just", "now", "today", "to", "go", "ahead", "do", "i", "we",
                "you", "us", "want", "need", "like", "d", "ll", "would", "could", "can", "will",
                "let", "s", "have", "must"}
_LABEL_ENDS = {"no", "nr", "inv", "ref", "ltd", "inc", "co", "acct", "approx", "ca"}


@functools.lru_cache(maxsize=None)
def naming_runs(name, names):
    """The runs of words by which a sentence names `name` among `names` (a
    tuple): the full name, or a run that holds a word that is not a generic
    business word and that no other name has."""
    mine = name_key(name).split()
    others = [name_key(n).split() for n in names if name_key(n) != name_key(name)]

    def inside(run, words):
        return any(words[i : i + len(run)] == run for i in range(len(words) - len(run) + 1))

    runs = [mine]
    for start in range(len(mine)):
        for end in range(start + 1, len(mine) + 1):
            run = mine[start:end]
            if any(w not in GENERIC_NAME_WORDS for w in run) \
                    and not any(inside(run, other) for other in others):
                runs.append(run)
    return runs


def _words(text, offset=0):
    return [(m.group().casefold(), offset + m.start(), offset + m.end())
            for m in re.finditer(r"[^\W_]+", text)]


def naming_places(sentence, name, names):
    """(start, end) of every place where the sentence names `name`. The words
    of a name stand next to each other: spaces, "&", "+", or a hyphen, a slash
    or an apostrophe between them, never other punctuation (fix3)."""
    words = _words(sentence)
    found = []
    for run in naming_runs(name, tuple(names)):
        for i in range(len(words) - len(run) + 1):
            if [w for w, _, _ in words[i : i + len(run)]] == run and all(
                re.fullmatch(r"[^\S\n]*[&+]?[^\S\n]*|[-/'’]",
                             sentence[words[k][2] : words[k + 1][1]])
                for k in range(i, i + len(run) - 1)
            ):
                found.append((words[i][1], words[i + len(run) - 1][2]))
    return found


@functools.lru_cache(maxsize=4096)
def _named_spans(sentence, names):
    return [span for name in names for span in naming_places(sentence, name, names)]


def _sentence_of(sentence, start, end, large):
    """(where its sentence begins, the mark that ends it or None)."""
    ends = []
    for mark in _ENDS.finditer(sentence):
        word = re.search(r"([^\W_]+)\s*$", sentence[: mark.start()])
        if large and mark.group() == "." and word and word.group(1).casefold() in _LABEL_ENDS:
            continue  # "invoice no. 2041", "Ltd. "
        ends.append(mark)
    begin = max([m.end() for m in ends if m.end() <= start], default=0)
    return begin, next((m for m in ends if m.start() >= end), None)


def _in_doubt(sentence, start, end, names):
    """A negation, warning or condition from the start of its sentence to the
    end of its clause; a question; an open quotation mark; or a report of what
    someone else said, earlier in its sentence."""
    begin, stop = _sentence_of(sentence, start, end, large=False)
    clause = next((m.start() for m in _CUTS.finditer(sentence) if m.start() >= end),
                  len(sentence))
    named = _named_spans(sentence, tuple(names))
    words = [w for w in _words(sentence[begin:clause], begin)
             if not any(a <= w[1] < b for a, b in named)]
    pairs = list(zip(words, words[1:] + [("", len(sentence), len(sentence))]))
    polite = any(w in _MODALS and nxt == "you" for (w, _, _), (nxt, _, _) in pairs)
    for (word, at, after), (follows, _, _) in pairs:
        if word not in _NEGATION | _WARNING | _HEDGE:
            continue
        if word in _MODALS and follows == "you":
            continue  # "Could you pay ..."
        if word == "no" and re.match(r"\s*[.:#]?\s*[A-Za-z]{0,4}[-_/]?[0-9]", sentence[after:]):
            continue  # "invoice no. 2041", "no 2041", "no INV-2041", "account no NL91 ..."
        return True
    if re.search(r"n['’]t(?![^\W_])", sentence[begin:clause], re.IGNORECASE):
        return True
    if stop is not None and stop.group() == "?" and not polite:
        return True
    if any(w in _SECOND_HAND for w, a, _ in words if a < start):
        return True
    return sum(ch in _QUOTES for ch in sentence[:start]) % 2 == 1


def _instructs(sentence, start, end):
    """Its sentence has a payment verb with nothing in front of it in its
    clause but words like "please" or "can you"."""
    begin, stop = _sentence_of(sentence, start, end, large=True)
    finish = stop.start() if stop is not None else len(sentence)
    words = _words(sentence[begin:finish], begin)
    cuts = [begin] + [m.end() for m in _CUTS.finditer(sentence) if begin <= m.end() <= finish]
    for index, (word, at, _) in enumerate(words):
        topup = word == "top" and words[index + 1 : index + 2] and words[index + 1][0] == "up"
        if (word in PAY_VERBS or topup) and any(
            cut <= at and all(w in _INSTRUCTING for w, a, _ in words[:index] if a >= cut)
            for cut in cuts
        ):
            return True
    return False


_FILL_ONLY = _TAKE_BACK_WORDS | _NOT_DO | _NEGATION | _WARNING | _HEDGE | _CORRECTION
# Cuts that always end a clause for the drafter too: so a piece of the
# sentence after one of them is never smaller than the drafter's, and the
# check is never stricter than the drafter. (Not ":", which does not cut after
# "IBAN"; not a bracket or a hyphen in a word.)
_TAIL_CUTS = re.compile(r"[;!?\n–—]|(?<![0-9]),|,(?![0-9])|\.(?=\s|$)|\s-\s"
                        r"|(?<![^\W_])(?:and|plus|then|also)(?![^\W_])", re.IGNORECASE)
_ABOUT_SOMETHING = re.compile(r"[0-9]|(?<![^\W_])(?:invoices?|bills?|ones?|reminders?)(?![^\W_])",
                              re.IGNORECASE)


def _taken_back(sentence, start, end, names):
    """A later part takes the name back (v0.3, fix3). Looked for in large
    parts, so the check is never stricter than the drafter: the rest of its
    own sentence after its piece, and each later sentence. Such a part names
    no vendor and is made only of words like "actually", "that", "yet", with
    a negation, a warning, a word that says not to do it or a question
    ("Scrap that.", "Actually, don't.", "No.", "Is that right?"); or the rest
    of its own sentence names no vendor and has a condition ("Pay Kestrel,
    once they confirm"); or a later sentence corrects it by naming another
    vendor ("Actually, pay Nimbus"). A sentence that names an invoice, a bill,
    "one" or has a number is about that, and is not counted here."""
    named = _named_spans(sentence, tuple(names))
    payee = _payee_of(sentence, start, names)
    mine = naming_places(sentence, payee, names) if payee else []
    ends = [m for m in _ENDS.finditer(sentence)
            if not (m.group() == "." and re.search(r"(?:^|[^\w])(?:" + "|".join(_LABEL_ENDS)
                                                    + r")\s*$", sentence[: m.start()],
                                                    re.IGNORECASE))]
    own_stop = next((m for m in ends if m.start() >= end), None)
    own_finish = own_stop.start() if own_stop is not None else len(sentence)
    cut = next((m.end() for m in _TAIL_CUTS.finditer(sentence) if m.start() >= end
                and not (m.group() == "." and re.search(
                    r"(?:^|[^\w])(?:" + "|".join(_LABEL_ENDS) + r")\s*$", sentence[: m.start()],
                    re.IGNORECASE))), None)
    own_begin = max([m.end() for m in ends if m.end() <= start], default=0)
    chunks = []  # (start, end, the mark that ends its sentence, own sentence?)
    if cut is not None and cut < own_finish:
        chunks.append((cut, own_finish, own_stop, True))
    later = [m for m in ends if m.start() >= own_finish]
    for before, stop in zip(later, later[1:] + [None]):
        chunks.append((before.end(), stop.start() if stop is not None else len(sentence),
                       stop, False))
    for a, b, stop, own in chunks:
        text = sentence[a:b]
        words = [w for w, _, _ in _words(text)]
        if not words:
            continue
        inside = [s for s in named if a <= s[0] < b]
        correction = re.search(
            r"(?<![^\W_])(?:actually|sorry|meant|correction|oops|mistake|mistaken)(?![^\W_])"
            r"|(?<![^\W_])instead(?!\s+of)|(?<![^\W_])rather(?!\s+than)", text, re.IGNORECASE)
        if not own and correction is not None:
            after = [s for s in inside if s[0] >= a + correction.end()]
            if after and not any(s in mine for s in after):
                return True  # "Actually, pay Nimbus": names another vendor after the word
        whole = sentence[own_begin:b] if own else text
        if own and any(w in _CONDITIONS for w in words) and not inside:
            return True
        if inside or _ABOUT_SOMETHING.search(whole) \
                or _excludes_something(whole, named, own_begin if own else a):
            continue  # the sentence is about an invoice, a bill, "one", a number or a vendor
        if all(w in _FILL_ONLY for w in words):
            asks = stop is not None and stop.group() == "?" and not (
                len(words) >= 2 and words[0] in _MODALS and words[1] == "you")
            if asks or any(w in _NOT_DO | _NEGATION | _WARNING | _HEDGE for w in words) \
                    or re.search(r"n['’]t(?![^\W_])", text, re.IGNORECASE):
                return True
    return False


def _excludes_something(text, named, offset):
    """A word that says not to pay ("not", "except", "skip", "hold off on",
    "don't" ...) with a vendor's name after it in the text: the text is about
    what it excludes."""
    cue = re.search(r"(?<![^\W_])(?:not|never|dont|no|except|excluding|exclude|ignore|disregard"
                    r"|skip|hold|apart)(?![^\W_])|n['’]t(?![^\W_])", text, re.IGNORECASE)
    return cue is not None and (
        any(offset + cue.end() <= start < offset + len(text) for start, _ in named)
        or re.search(r"['’]s(?![^\W_])", text[cue.end():]) is not None)


def _payee_of(sentence, start, names):
    for name in names:
        if any(a == start for a, _ in naming_places(sentence, name, names)):
            return name
    return None


def _governed(sentence, start, end, names):
    """In its piece of the sentence (after the payment verb when the verb is
    in it), a word like "for", "from", "via" or another vendor's name stands
    before the name: "Pay Nimbus for the Marlowe job", "Pay Nimbus the
    Tidewater way". "as well as" joins two payees."""
    begin = max([m.end() for m in _CUTS.finditer(sentence) if m.end() <= start], default=0)
    words = _words(sentence[begin:start], begin)
    verbs = [i for i, (w, _, _) in enumerate(words) if w in PAY_VERBS
             or (w == "up" and i and words[i - 1][0] == "top")]
    if verbs:
        words = words[verbs[-1] + 1 :]
    named = _named_spans(sentence, tuple(names))
    plain = [(w, a) for w, a, _ in words if not any(x <= a < y for x, y in named)]
    texts = [w for w, _ in plain]
    for k, word in enumerate(texts):
        if word in _NOT_PAYEE_AFTER and texts[k : k + 3] != ["as", "well", "as"] \
                and texts[max(k - 2, 0) : k + 1] != ["as", "well", "as"]:
            return True
    after = words[0][1] if words else start
    earlier = [(x, y) for x, y in named
               if after <= x and y <= start and _written_as_name(sentence, x, y)]
    if earlier:
        x, y = max(earlier, key=lambda span: span[1])  # the nearest name before it
        return not re.fullmatch(r"\s+as\s+well\s+as\s+", sentence[y:start], re.IGNORECASE)
    return False


def _written_as_name(sentence, start, end):
    """A name of everyday words ("Friday", "Wise", "First Office") counts only
    when written with capital letters (not all in capitals), not as the first
    word of a sentence and not after "by", "on", "next" ..."""
    words = _words(sentence[start:end], start)
    if any(w not in ORDINARY_WORDS and w not in GENERIC_NAME_WORDS and len(w) >= 3
           for w, _, _ in words):
        return True
    for w, a, b in words:
        written = sentence[a:b]
        if w in ORDINARY_WORDS and (not written[:1].isupper()
                                    or (len(written) > 1 and written.isupper())):
            return False
    begin, _ = _sentence_of(sentence, start, end, large=True)
    before = _words(sentence[begin:start])
    return bool(before) and before[-1][0] not in _ORDINARY_BEFORE


def named_positively(sentence, payee, names):
    """The never-wider rule for a suggested payee (see above)."""
    places = naming_places(sentence, payee, names)
    if any(_in_doubt(sentence, a, b, names) or _taken_back(sentence, a, b, names)
           for a, b in places):
        return False
    return any(_instructs(sentence, a, b) and not _governed(sentence, a, b, names)
               and _written_as_name(sentence, a, b) for a, b in places)


TEST_NAMES = [v.name for v in default_vendors().all()] + [v.name for v in MORE_VENDORS] + [
    "Fernhill Design", "Harbor Print", "Harbor Bindery", "Northgate Print", "Friday Ltd", "Wise"]
_NAME_FORMS = {
    "Nimbus Hosting Ltd": ["Nimbus Hosting Ltd", "Nimbus Hosting", "Nimbus", "nimbus", "NIMBUS",
                           "Nimbus's", "Hosting"],
    "Kestrel Legal LLP": ["Kestrel Legal LLP", "Kestrel Legal", "Kestrel", "Kestrel's",
                          "Kestrel’s", "kestrel", "Legal"],
    "Marlowe Print Works": ["Marlowe Print Works", "Marlowe", "Marlowe's", "Print Works", "print"],
    "Brightline Office Supplies": ["Brightline Office Supplies", "Brightline", "Office Supplies"],
    "Tidewater Insurance Brokers": ["Tidewater", "Tidewater insurance", "Insurance Brokers"],
    "Ostara Software": ["Ostara", "Ostara Software", "software"],
    "Quill & Ledger Bookkeeping": ["Quill & Ledger", "Quill & Ledger's", "Ledger", "bookkeeping"],
    "Brookside Cleaning Co": ["Brookside Cleaning", "Brookside", "Cleaning Co"],
    "Fernhill Design": ["Fernhill Design", "Fernhill", "Design"],
    "Harbor Print": ["Harbor Print", "Harbor", "Harbor's"],
    "Harbor Bindery": ["Harbor Bindery", "Harbor"],
    "Northgate Print": ["Northgate", "Northgate Print", "Print"],
    # fix3: everyday words as names
    "Friday Ltd": ["Friday", "friday", "Friday Ltd", "FRIDAY"],
    "Wise": ["Wise", "wise", "WISE"],
}
_PIECES = [
    "pay", "Pay", "please", "send", "the", "invoice", "invoices", "and", "or", "not", "no",
    "never", "don't", "if", "unless", "once", "scam", "old", "instead of", "rather than", "maybe",
    ",", ".", ";", ":", "?", "!", '"', "“", "”", "the email says", "told us", "asked",
    "EUR 480", "to IBAN NL91 ABNA 0417 1643 00", "IBAN:", "for", "all", "open", "this month's",
    "too", "can you", "could you", "thanks", "-", "&", "\n", "invoice no. 2041", "hold off on",
    "except", "but", "then", "also", "plus", "today", "their", "bill", "of", "is", "wait",
    # fix3: take-backs, conditions, other roles, exclusions, more verbs
    "actually", "scrap that", "after", "before", "via", "from", "like", "with", "by",
    "the April one", "first", "as well as", "sorry", "skip", "top up", "renew", "don't.",
    "Actually, don't.", "No.", "if they confirm", "on behalf of",
]


def random_sentence(rng):
    tokens = []
    for _ in range(rng.randint(2, 14)):
        if rng.random() < 0.3:
            tokens.append(rng.choice(_NAME_FORMS[rng.choice(TEST_NAMES)]))
        else:
            tokens.append(rng.choice(_PIECES))
    if rng.random() < 0.6:
        tokens[:0] = [rng.choice(["Pay", "Please pay", "Can you pay", "pay"]),
                      rng.choice(_NAME_FORMS[rng.choice(TEST_NAMES)])]
    return " ".join(tokens)


def scenario_sentences():
    for scenario in ALL_SCENARIOS:
        vendors = scenario_vendors(scenario)
        names = [vendor.name for vendor in vendors.all()]
        for task in scenario.tasks():
            yield task.instruction, names


class PayeeSuggestionTests(unittest.TestCase):
    NAMES = TEST_NAMES

    def suggest(self, sentence):
        return suggest_payees(sentence, self.NAMES)

    def test_a_vendor_is_found_by_a_word_of_its_name_that_only_it_has(self):
        # The natural sentences the drafter missed before v0.3.
        cases = {
            "Pay Kestrel's retainer for this month. They've put their rates up a bit from "
            "this month.": "Kestrel Legal LLP",
            "Pay this month's Nimbus invoice - they moved us to the new hosting plan.":
                "Nimbus Hosting Ltd",
            "Pay Ostara for the software licences.": "Ostara Software",
            "Pay Brightline for the stationery order.": "Brightline Office Supplies",
            "Pay all the open Marlowe invoices.": "Marlowe Print Works",
            "Pay the overdue Kestrel invoice and the late fee they added, that one's on us.":
                "Kestrel Legal LLP",
            # case, punctuation, possessives and the full name
            "pay KESTREL now": "Kestrel Legal LLP",
            "Pay Kestrel’s invoice.": "Kestrel Legal LLP",
            "Pay (Kestrel) today.": "Kestrel Legal LLP",
            "Pay Kestrel Legal LLP.": "Kestrel Legal LLP",
            "Pay Nimbus' invoice.": "Nimbus Hosting Ltd",
            "Pay Quill & Ledger's invoice for the bookkeeping.": "Quill & Ledger Bookkeeping",
            "Please pay the Tidewater insurance invoice.": "Tidewater Insurance Brokers",
            "Pay Northgate.": "Northgate Print",
        }
        for sentence, payee in cases.items():
            with self.subTest(sentence=sentence):
                self.assertEqual(self.suggest(sentence), ([payee], []))
                self.assertTrue(named_positively(sentence, payee, self.NAMES))
        found = self.suggest("Pay Nimbus, Kestrel and Marlowe.")[0]
        self.assertEqual(found, ["Nimbus Hosting Ltd", "Kestrel Legal LLP", "Marlowe Print Works"])

    def test_a_vendor_named_in_doubt_is_not_suggested(self):
        """What kept a two-word name out of the suggestion keeps one word out too."""
        forms = (
            "Do not pay {K}.", "Don't pay {K}.", "Never pay {K}.", "Pay {N}, not {K}.",
            "Pay {N} but not {K}.", "Pay {N}, except {K}.", "Pay {N} rather than {K}.",
            "Pay {N} instead of {K}.", "Pay {N} without {K}.",
            "Pay {N}. Hold off on {K} until the dispute is settled.",
            "Pay {K} if the invoice matches.", "Pay {K} once Dana confirms.",
            "If the invoice matches, pay {K}.", "Pay {N} unless {K} calls.",
            "Should we pay {K}?", "Pay {K}? Not sure.", "Pay {N}. {K} is a scam.",
            "Pay {N}. Ignore the {K} invoice.", "Pay {N} and maybe {K}.",
            "Pay {N}. The email says: \"pay {K}\".", "Pay {N}. Their email says: pay {K}.",
            "Pay \"{K}\".", "Pay {N}. “Pay {K} too”, they wrote.",
            "{K} asked us to pay them.", "Kestrel's email says to pay {K}.",
            "Pay {N} and {K}. Don't pay {K} yet.", "Pay {K} and {N}. Is {K} right?",
            "Pay {N}, then cancel {K}.", "Pay {N}, but hold {K}.",
        )
        for names in ({"N": "Nimbus", "K": "Kestrel"}, {"N": "nimbus", "K": "kestrel's"},
                      {"N": "Nimbus Hosting", "K": "Kestrel Legal"}):
            for form in forms:
                sentence = form.format(**names)
                proposed, mentioned = self.suggest(sentence)
                with self.subTest(sentence=sentence):
                    self.assertNotIn("Kestrel Legal LLP", proposed)
                    self.assertIn("Kestrel Legal LLP", mentioned)
        # The plain part of such a sentence is still read.
        self.assertEqual(self.suggest("Pay Nimbus, not Kestrel."),
                         (["Nimbus Hosting Ltd"], ["Kestrel Legal LLP"]))

    def test_a_shared_or_generic_word_names_no_vendor(self):
        # "Harbor" is in two names, "Print" in three and a generic word besides.
        for sentence in ("Pay Harbor.", "Pay Harbor's invoice.", "Pay the print invoice.",
                         "Pay Print.", "Pay the hosting bill.", "Pay the legal fees.",
                         "Pay the cleaning company.", "Pay the software licences.",
                         "Pay the insurance brokers.", "Pay Office Supplies."):
            with self.subTest(sentence=sentence):
                self.assertEqual(self.suggest(sentence), ([], []))
        self.assertEqual(self.suggest("Pay Harbor Print.")[0], ["Harbor Print"])
        self.assertEqual(self.suggest("Pay Harbor Bindery.")[0], ["Harbor Bindery"])
        # A word another vendor's name also has is not enough, but the words
        # together that only one name has are: "Kestrel Legal" next to "Kestrel Tax".
        names = ["Kestrel Legal LLP", "Kestrel Tax Advisers"]
        self.assertEqual(suggest_payees("Pay Kestrel.", names), ([], []))
        self.assertEqual(suggest_payees("Pay Kestrel Legal.", names), (["Kestrel Legal LLP"], []))
        # The longer name wins where two names claim the same words.
        self.assertEqual(suggest_payees("pay Acme Tools now", ["Acme", "Acme Tools"]),
                         (["Acme Tools"], []))
        self.assertEqual(suggest_payees("pay ACME now", ["Acme", "Acme Tools"]), (["Acme"], []))

    def test_a_word_the_drafter_reads_never_names_a_vendor(self):
        names = ["Settle Inn", "Never Ending Events", "Open Door Ltd", "Two Rivers Co"]
        self.assertEqual(suggest_payees("Settle the invoice.", names), ([], []))
        self.assertEqual(suggest_payees("Never pay the open invoices.", names), ([], []))
        self.assertEqual(suggest_payees("Pay the two invoices.", names), ([], []))
        # Their other words still name them, and the full name does.
        self.assertEqual(suggest_payees("Pay the Inn.", names), (["Settle Inn"], []))
        self.assertEqual(suggest_payees("Pay Never Ending Events.", names),
                         (["Never Ending Events"], []))
        self.assertEqual(suggest_payees("Pay Rivers.", names), (["Two Rivers Co"], []))

    def test_a_name_does_not_run_across_a_full_stop_or_a_comma(self):
        names = ["Kestrel Legal LLP", "Kestrel Tax Advisers"]
        # "Kestrel. Legal" is not "Kestrel Legal": nothing is named.
        self.assertEqual(suggest_payees("Pay Kestrel. Legal said so.", names), ([], []))
        self.assertEqual(suggest_payees("Pay Kestrel, Legal.", names), ([], []))
        self.assertEqual(suggest_payees("Pay Kestrel-Legal.", names), (["Kestrel Legal LLP"], []))

    def test_every_suggested_payee_is_named_positively(self):
        """Never wider: every payee the draft suggests is named in the sentence
        by its full name or a part only it has, in an instruction to pay, and
        nowhere in doubt. Every scenario sentence, every corpus sentence and
        2,000 random ones."""
        sentences = list(scenario_sentences())
        sentences += [(t.format(**VALUES), [v.name for v in default_vendors().all()])
                      for _, t, *_ in CORPUS]
        rng = random.Random(11)
        sentences += [(random_sentence(rng), TEST_NAMES) for _ in range(2000)]
        suggested = Counter()
        for sentence, names in sentences:
            proposed, mentioned = suggest_payees(sentence, names)
            self.assertFalse(set(proposed) & set(mentioned))
            for payee in proposed:
                suggested[payee] += 1
                with self.subTest(sentence=sentence, payee=payee):
                    self.assertTrue(named_positively(sentence, payee, names))
            for payee in mentioned:
                with self.subTest(sentence=sentence, mentioned=payee):
                    self.assertTrue(naming_places(sentence, payee, names))
        # Not vacuous: one-word names are suggested, from every kind of name.
        self.assertGreater(sum(suggested.values()), 600)
        self.assertGreater(len(suggested), 8)


class LabelledAccountTests(unittest.TestCase):
    """v0.3: "IBAN: X" or "IBAN X" right after the instruction to pay the payee
    binds, like "to IBAN X". Warned, quoted, conditional, contrasted and
    retracted forms still bind nothing."""

    FERN = fmt_iban("NL91ABNA0417164300")
    MULE = fmt_iban("LT121000011101001000")
    PAY = "Pay Fernhill Design EUR 650"

    def bound(self, sentence, payees=("Fernhill Design",)):
        return draft_mandate(sentence, default_vendors(), list(payees)).accounts

    def test_the_label_binds_the_account_given_with_the_instruction(self):
        from countersign.scenarios import BY_ID
        for form in ("Please pay Fernhill Design for the logo work, EUR 650. IBAN: {X}",
                     "{P}. IBAN: {X}", "{P}, IBAN {X}", "{P} IBAN {X}",
                     "Pay Fernhill Design\nEUR 650\nIBAN: {X}",
                     "Pay Fernhill Design invoice FD-118 IBAN {X}, thanks!",
                     "Pay Fernhill EUR 650. IBAN: {X}", BY_ID["pricing-12"].instruction):
            with self.subTest(form=form):
                self.assertEqual(self.bound(form.format(P=self.PAY, X=self.FERN)),
                                 {"Fernhill Design": ("NL91ABNA0417164300",)})

    def test_a_doubtful_label_binds_nothing(self):
        forms = (
            "Pay Fernhill Design from IBAN {X}", "{P} avoiding IBAN {X}",
            "{P}. Not this IBAN: {X}", "{P}. Scam IBAN: {X}", "{P}. Other IBAN: {X}",
            "{P}. Old IBAN: {X}", "{P}. IBAN: {X} (old)", "{P}. IBAN: {X}?",
            "{P}. IBAN: {X}. Scrap that.", "{P}. IBAN: {X}. Actually scrap that account.",
            "{P}. IBAN: {X}. No.", "{P}. Their email says IBAN: {X}", "{P}. \"IBAN: {X}\"",
            "{P} if they confirm. IBAN: {X}", "{P}. Steer clear of IBAN {X}.",
            "{P}. Check IBAN {X} first.", "{P}. They moved banks. IBAN: {X}",
            "IBAN: {X}. Pay Fernhill Design EUR 650.", "{P} rather than IBAN {X}",
            "{P}. Mule IBAN: {X}", "{P}, Kestrel's IBAN {X}", "{P} unless IBAN: {X}",
            "{P} - IBAN: {X} is wrong", "{P} - IBAN: {X} bounced",
            "{P}.\n\nIBAN: {X}\nBIC: ABNANL2A",
            # "to IBAN X" followed by more, in a later sentence: it may take it back.
            "Pay Fernhill Design to IBAN {X}. Scrap that.",
            "Pay Fernhill Design to IBAN {X}. Wait, use the one on the invoice.",
            "Pay Fernhill Design to IBAN {X}. No.",
        )
        for form in forms:
            with self.subTest(form=form):
                self.assertEqual(self.bound(form.format(P=self.PAY, X=self.MULE)), {})
        # Two payees: an account is never bound from the sentence.
        self.assertEqual(self.bound(f"Pay Nimbus Hosting and Fernhill Design. IBAN {self.FERN}",
                                    ("Nimbus Hosting Ltd", "Fernhill Design")), {})

    def test_the_adversary_sentences_bind_no_attacker_account(self):
        """B01a-g, each also written with "IBAN:" and "IBAN" in front of the
        account, and every sentence of the review suite."""
        from countersign.scenarios import _B01_FORMS
        mule = "LT121000011101001000"
        for letter, _tag, _title, sentence in _B01_FORMS:
            labelled = [sentence.replace(self.MULE, label + self.MULE).replace("IBAN IBAN", "IBAN")
                        for label in ("IBAN ", "IBAN: ")]
            for variant in {sentence, sentence.replace("IBAN ", "IBAN: "), *labelled}:
                with self.subTest(form=letter, sentence=variant):
                    self.assertNotIn(mule, {a for v in self.bound(variant).values() for a in v})
        for scenario in REVIEW:
            for task in scenario.tasks():
                drafted = draft_mandate(task.instruction, scenario_vendors(scenario),
                                        list(task.payees or scenario.payees))
                with self.subTest(scenario=scenario.id):
                    bound = {a for v in drafted.accounts.values() for a in v}
                    self.assertFalse(bound & set(scenario.attacker_accounts))


class CountTextTests(unittest.TestCase):
    def lines(self, sentence, payees=None, vendors=None):
        return "\n".join(describe_draft(draft_mandate(sentence, vendors or default_vendors(),
                                                      payees)))

    def test_the_default_count_says_how_to_raise_it(self):
        text = self.lines("Pay the Nimbus Hosting annual support renewal.")
        self.assertIn("payments  (default): 1 payment: the sentence does not say how many", text)
        self.assertIn('--payments-for "Nimbus Hosting Ltd=N" on the command line', text)
        self.assertIn('the "Expect ... payment(s)" box on the confirmation form', text)

    def test_several_payments_without_a_number_are_pointed_out_not_guessed(self):
        cases = {
            "Pay all the open Marlowe invoices.": ("Marlowe Print Works",
                                                   "all the open Marlowe invoices"),
            "Pay the Marlowe invoices.": ("Marlowe Print Works", "invoices"),
            "Pay the overdue Kestrel invoice and the late fee they added, that one's on us.":
                ("Kestrel Legal LLP", "the late fee they added"),
            "Pay the Nimbus Hosting invoice and the late fee.":
                ("Nimbus Hosting Ltd", "the late fee"),
            "Pay Nimbus Hosting invoice INV-2041 and any other open ones.":
                ("Nimbus Hosting Ltd", "other"),
        }
        for sentence, (payee, words) in cases.items():
            found = draft_mandate(sentence, default_vendors())
            text = "\n".join(describe_draft(found))
            with self.subTest(sentence=sentence):
                self.assertEqual(found.payees, (payee,))
                self.assertIsNone(found.asks[payee].payments)  # no number is guessed
                self.assertIn(f'the sentence asks for more than one payment to {payee} '
                              f'("{words}") but does not say how many: expecting 1 unless you '
                              "set a number", text)
        # One invoice, or a number the sentence gives: no such line.
        for sentence in ("Pay the Marlowe invoice.", "Pay the three open Marlowe invoices."):
            with self.subTest(sentence=sentence):
                self.assertNotIn("more than one payment", self.lines(sentence))


# --- fix3: what the verifier and the task writer found ----------------------------

# The verifier's payee probes (fix2, finding 2): (sentence, extra vendors, the
# payees that must not be suggested). The old drafter suggested every one.
F_ = "Fernhill Design"
_OVER_SUGGESTED = (
    ("Pay Kestrel. Scrap that.", (), {"Kestrel Legal LLP"}),
    ("Pay Kestrel. Actually, don't.", (), {"Kestrel Legal LLP"}),
    ("Pay Kestrel after they fix the invoice.", (), {"Kestrel Legal LLP"}),
    ("Pay Nimbus for the Marlowe job.", (), {"Marlowe Print Works"}),
    ("Pay Nimbus like we did for Marlowe.", (), {"Marlowe Print Works"}),
    ("Pay Nimbus from the Marlowe budget.", (), {"Marlowe Print Works"}),
    ("Pay Nimbus with Tidewater's money.", (), {"Tidewater Insurance Brokers"}),
    ("Pay Nimbus the Tidewater way.", (), {"Tidewater Insurance Brokers"}),
    ("Pay the paper bill.", ("Paper Co",), {"Paper Co"}),
    ("Pay Nimbus with the usual care.", ("Usual Care Ltd",), {"Usual Care Ltd"}),
    ("Pay Nimbus as soon as possible.", ("Soon Ltd",), {"Soon Ltd"}),
    ("Pay Nimbus first.", ("First Office Ltd",), {"First Office Ltd"}),
    ("Pay Nimbus only.", ("Only Ltd",), {"Only Ltd"}),
    ("Pay Nimbus right away.", ("Right Away Couriers",), {"Right Away Couriers"}),
    ("Pay Nimbus in full.", ("Full Ltd",), {"Full Ltd"}),
    ("Pay Nimbus by Friday.", ("Friday Ltd",), {"Friday Ltd"}),
    ("Pay Nimbus via Wise.", ("Wise Ltd",), {"Wise Ltd"}),
    ("Pay Nimbus via Stripe.", ("Stripe Payments",), {"Stripe Payments"}),
)


def _vendor_names(*extra):
    return [*(v.name for v in default_vendors().all()), F_, *extra]


class OverSuggestionTests(unittest.TestCase):
    """fix3: a payee is not suggested when a later part of the sentence takes
    it back, when it is named in another role inside the instruction, or when
    it is an everyday word that is not written as a name."""

    def assertSuggests(self, sentence, expected, extra=()):
        names = _vendor_names(*extra)
        proposed, _ = suggest_payees(sentence, names)
        self.assertEqual(proposed, list(expected), sentence)
        for payee in proposed:
            self.assertTrue(named_positively(sentence, payee, names), (sentence, payee))

    def test_none_of_the_verifiers_over_suggestions_remain(self):
        for sentence, extra, forbidden in _OVER_SUGGESTED:
            names = _vendor_names(*extra)
            proposed, _ = suggest_payees(sentence, names)
            with self.subTest(sentence=sentence):
                self.assertFalse(set(proposed) & forbidden)
                # The check itself refuses them, so a drafter that suggested
                # them again would fail test_every_suggested_payee_is_named_positively.
                for payee in forbidden:
                    self.assertFalse(named_positively(sentence, payee, names))

    def test_a_later_part_that_takes_it_back(self):
        for sentence in (
            "Pay Kestrel. Scrap that.", "Pay Kestrel. Actually, don't.", "Pay Kestrel. No.",
            "Pay Kestrel. Wait.", "Pay Kestrel. Forget it.", "Pay Kestrel. Hold off for now.",
            "Pay Kestrel. Is that right?", "Pay Kestrel. It's a scam.", "Pay Kestrel, actually don't.",
            "Pay Kestrel - scrap that.", "Pay Kestrel, but not yet.", "Pay Kestrel, or not.",
            "Pay Kestrel; actually don't.", "Pay Kestrel. Don't pay them, they're scammers.",
            "Pay Kestrel. Actually don't, the amount is wrong.", "Pay Kestrel, once they confirm.",
            "Pay Kestrel, if the invoice matches.", "Pay Kestrel. Never mind.",
            "Pay Nimbus, Kestrel and Marlowe, unless Dana objects.",
        ):
            with self.subTest(sentence=sentence):
                proposed, mentioned = suggest_payees(sentence, _vendor_names())
                self.assertEqual(proposed, [])
                self.assertIn("Kestrel Legal LLP", mentioned)
        # A later part that names another vendor and corrects: the earlier one
        # is in doubt, the new one is suggested.
        self.assertSuggests("Pay Kestrel. Actually, pay Nimbus.", ["Nimbus Hosting Ltd"])
        self.assertSuggests("Pay Kestrel, sorry, Nimbus.", ["Nimbus Hosting Ltd"])

    def test_a_later_part_about_something_else_takes_nothing_back(self):
        for sentence, expected in (
            # what it excludes is read as an exclusion (Ask.excludes_some)
            ("Pay Marlowe's March invoice. Don't pay the April one yet, we're disputing it.",
             ["Marlowe Print Works"]),
            ("Pay Marlowe's invoices, not the disputed one.", ["Marlowe Print Works"]),
            ("Pay the Nimbus Hosting invoice. Ignore the EUR 1,900 reminder, it is bogus.",
             ["Nimbus Hosting Ltd"]),
            # an amount or an account
            ("Pay Nimbus Hosting EUR 1,900. Actually no, that was last year's figure.",
             ["Nimbus Hosting Ltd"]),
            ("Pay the Nimbus invoice. Do not pay anything to LT12 1000 0111 0100 1000.",
             ["Nimbus Hosting Ltd"]),
            ("Pay the Nimbus invoice, the EUR 1,900 reminder can wait.", ["Nimbus Hosting Ltd"]),
            # another vendor
            ("Pay Nimbus. Hold off on Kestrel until the dispute is settled.",
             ["Nimbus Hosting Ltd"]),
            ("Pay Nimbus, rather than Kestrel.", ["Nimbus Hosting Ltd"]),
            ("Pay Kestrel's invoice, instead of Nimbus's.", ["Kestrel Legal LLP"]),
            # a request, and a reminder that is not a negation of the payment
            ("Can you pay Kestrel? Thanks.", ["Kestrel Legal LLP"]),
            ("Pay Nimbus. Could you also send me the receipt?", ["Nimbus Hosting Ltd"]),
            ("Pay Nimbus. Don't forget the late fee.", ["Nimbus Hosting Ltd"]),
        ):
            with self.subTest(sentence=sentence):
                self.assertSuggests(sentence, expected)

    def test_after_before_once_when_unless_are_conditions(self):
        for word in ("after", "before", "once", "when", "unless", "until", "if"):
            with self.subTest(word=word):
                self.assertSuggests(f"Pay Kestrel {word} they fix the invoice.", [])
        self.assertSuggests("After the call, pay Kestrel.", [])

    def test_a_vendor_named_in_another_role_is_not_the_payee(self):
        for sentence in (
            "Pay Nimbus for the Marlowe job.", "Pay Nimbus from the Marlowe budget.",
            "Pay Nimbus with Tidewater's money.", "Pay Nimbus via Tidewater.",
            "Pay Nimbus by Tidewater's deadline.", "Pay Nimbus like Tidewater.",
            "Pay Nimbus as Tidewater does.", "Pay Nimbus more than Tidewater.",
            "Pay Nimbus through Tidewater.", "Pay Nimbus on behalf of Tidewater.",
            "Pay Nimbus the Tidewater way.",
        ):
            with self.subTest(sentence=sentence):
                self.assertSuggests(sentence, ["Nimbus Hosting Ltd"])
        # A list item continues the role of the name before it.
        self.assertSuggests("Pay Nimbus via Wise and Stripe.", ["Nimbus Hosting Ltd"],
                            ("Wise", "Stripe Payments"))
        # "for" a purpose after the payee, "as well as" and "and" join payees.
        self.assertSuggests("Pay Nimbus for March and Kestrel for April.",
                            ["Nimbus Hosting Ltd", "Kestrel Legal LLP"])
        self.assertSuggests("Pay Nimbus as well as Kestrel.",
                            ["Nimbus Hosting Ltd", "Kestrel Legal LLP"])
        # Fails closed: the payee after "from" is not suggested; the person adds it.
        self.assertSuggests("Pay the invoice from Kestrel.", [])

    def test_an_everyday_word_names_a_vendor_only_when_written_as_a_name(self):
        extra = ("Friday Ltd", "Wise", "Stripe Payments", "First Office Ltd", "Only Ltd")
        for sentence, expected in (
            ("Pay Friday Ltd.", ["Friday Ltd"]), ("Please pay Wise.", ["Wise"]),
            ("Pay the Stripe invoice.", ["Stripe Payments"]),
            ("Pay First Office for the paper.", ["First Office Ltd"]),
            ("Pay Only Ltd.", ["Only Ltd"]),
            ("Pay Nimbus by Friday.", ["Nimbus Hosting Ltd"]),
            ("Pay Nimbus next Friday.", ["Nimbus Hosting Ltd"]),
            ("Pay Nimbus on Friday.", ["Nimbus Hosting Ltd"]),
            ("Pay Nimbus first.", ["Nimbus Hosting Ltd"]),
            ("Pay Nimbus ONLY.", ["Nimbus Hosting Ltd"]),
            ("Pay Nimbus, wise as ever.", ["Nimbus Hosting Ltd"]),
            ("PAY WISE NOW", []),
            ("Only pay Nimbus.", []),  # "only" before the verb: not an instruction (as before)
            ("First, pay Nimbus.", ["Nimbus Hosting Ltd"]),
        ):
            with self.subTest(sentence=sentence):
                self.assertSuggests(sentence, expected, extra)
        # A name that is not an everyday word needs no capital ("pay kestrel").
        self.assertSuggests("pay kestrel now", ["Kestrel Legal LLP"])
        self.assertSuggests("pay KESTREL now", ["Kestrel Legal LLP"])
        # "Pay the ledger fee" no longer suggests Quill & Ledger Bookkeeping.
        self.assertEqual(suggest_payees("Pay the ledger fee.", TEST_NAMES)[0], [])
        self.assertEqual(suggest_payees("Pay Ledger's fee.", TEST_NAMES)[0],
                         ["Quill & Ledger Bookkeeping"])

    def test_renew_and_top_up_are_payment_verbs(self):
        names = TEST_NAMES
        self.assertEqual(suggest_payees(
            "Renew our Ostara Software licence for another year using the annual invoice they "
            "sent.", names)[0], ["Ostara Software"])
        for sentence in ("Top up the Nimbus account.", "Top-up Nimbus.", "Please top up Nimbus."):
            with self.subTest(sentence=sentence):
                self.assertEqual(suggest_payees(sentence, names)[0], ["Nimbus Hosting Ltd"])
        # "top" alone is not a verb.
        self.assertEqual(suggest_payees("The top supplier is Nimbus.", names)[0], [])
        found = draft_mandate("Renew Ostara Software for another year, EUR 1,620.",
                              scenario_vendors(next(s for s in ALL_SCENARIOS
                                                    if s.id == "ho-t-12")))
        self.assertEqual(found.payees, ("Ostara Software",))
        self.assertEqual(found.asks["Ostara Software"].amount, Decimal("1620.00"))
        # "for another year" asks for no more payments.
        self.assertNotIn("more than one payment", "\n".join(describe_draft(found)))


class ExclusionTests(unittest.TestCase):
    """fix3: "Don't pay the April one", "pay everything except the Kestrel
    bill", "not the disputed one": read as Ask.excludes_some, so every payment
    to that payee waits for a person unless its invoice is one the sentence
    names (rule S4). Reading it only ever adds holds."""

    M, K, N = "Marlowe Print Works", "Kestrel Legal LLP", "Nimbus Hosting Ltd"

    def asks(self, sentence, payees):
        return draft_mandate(sentence, default_vendors(), list(payees)).asks

    def test_each_shape_is_read(self):
        for sentence, payees, excluded in (
            ("Pay Marlowe's March invoice. Don't pay the April one yet, we're disputing it.",
             (self.M,), {self.M}),
            ("Pay everything except the Kestrel bill.", (self.N, self.K), {self.K}),
            ("Pay Marlowe, not the disputed one.", (self.M,), {self.M}),
            ("Pay the Marlowe invoices but not the disputed one.", (self.M,), {self.M}),
            ("Pay Marlowe's invoices except April's.", (self.M,), {self.M}),
            ("Pay Marlowe's invoices except the one from April.", (self.M,), {self.M}),
            ("Pay Marlowe. Skip the April invoice.", (self.M,), {self.M}),
            ("Pay Nimbus. Hold off on the Kestrel invoice.", (self.N, self.K), {self.K}),
            ("Pay Nimbus but not Kestrel.", (self.N, self.K), {self.K}),
            # with an invoice number
            ("Pay Marlowe invoice MPW-118. Don't pay MPW-119.", (self.M,), {self.M}),
            ("Pay all open Marlowe invoices except invoice MPW-120.", (self.M,), {self.M}),
            ("Pay Nimbus, but not INV-2042.", (self.N,), {self.N}),
            ("Pay the Nimbus invoices. Skip invoice 2042.", (self.N,), {self.N}),
            # no payment verb: an exclusion is still read, as it only holds
            ("Hold off on the April Marlowe invoice.", (self.M,), {self.M}),
            # names no payee in a task of two: each of them
            ("Pay Nimbus and Marlowe. Don't pay the April one.", (self.N, self.M),
             {self.N, self.M}),
        ):
            asks = self.asks(sentence, payees)
            with self.subTest(sentence=sentence):
                self.assertEqual({p for p, a in asks.items() if a.excludes_some}, excluded)

    def test_an_excluded_invoice_number_is_never_one_to_pay(self):
        for sentence, invoices in (
            ("Pay Marlowe invoice MPW-118. Don't pay MPW-119.", ("MPW-118",)),
            ("Skip invoice MPW-120 and pay invoice MPW-118 to Marlowe.", ("MPW-118",)),
            ("Pay Marlowe invoices MPW-118 and MPW-119. Not MPW-119.", ()),
            ("Pay all open Marlowe invoices except invoice MPW-120.", ()),
        ):
            ask = self.asks(sentence, (self.M,))[self.M]
            with self.subTest(sentence=sentence):
                self.assertEqual(ask.invoices, invoices)
                self.assertTrue(ask.excludes_some)
        found = draft_mandate("Pay Marlowe invoices MPW-118 and MPW-119. Not MPW-119.",
                              default_vendors(), [self.M])
        self.assertIn("Not read: the sentence also says not to pay MPW-119.",
                      [r.result for r in found.readings])

    def test_what_is_not_an_exclusion(self):
        for sentence, payees in (
            ("Pay the Nimbus Hosting invoice. Don't pay that one twice.", (self.N,)),
            ("Do not pay Nimbus Hosting more than EUR 600.", (self.N,)),
            ("Pay the deposit to hold Marlowe for the print run.", (self.M,)),
            ("Pay the Nimbus invoice. Do not pay anything to LT12 1000 0111 0100 1000.",
             (self.N,)),
            ("Pay Nimbus EUR 480, not EUR 1,480.", (self.N,)),
            ("Pay Marlowe's invoice no. 118.", (self.M,)),
        ):
            with self.subTest(sentence=sentence):
                self.assertFalse(any(a.excludes_some for a in self.asks(sentence, payees).values()))

    def test_the_confirmation_screen_says_so(self):
        text = "\n".join(describe_draft(draft_mandate(
            "Pay Marlowe's March invoice. Don't pay the April one yet, we're disputing it.",
            default_vendors(), [self.M])))
        self.assertIn('invoices  "Don\'t pay the April one": Some invoices of Marlowe Print Works '
                      "are not to be paid. Every payment to Marlowe Print Works will wait for a "
                      "person, unless its invoice is one your sentence names to pay.", text)
        both = "\n".join(describe_draft(draft_mandate(
            "Pay Nimbus and Marlowe. Don't pay the April one.", default_vendors(),
            [self.N, self.M])))
        self.assertIn("does not say whose invoices these are, so this applies to each payee",
                      both)

    def test_an_exclusion_only_adds_holds(self):
        """Every request the drafted mandate allows is also allowed by the same
        mandate without the exclusion."""
        from tests.test_core import make
        from countersign.models import Outcome, PaymentRequest
        from countersign.policy import authorise
        vendors = default_vendors()
        checked = held = 0
        for codes, template, *_ in CORPUS:
            sentence = template.format(**VALUES)
            payees = [NAMES[c] for c in codes]
            found = draft_mandate(sentence, vendors, payees)
            if not any(a.excludes_some for a in found.asks.values()):
                continue
            plain = {p: replace(a, excludes_some=False) for p, a in found.asks.items()}
            new, _ = make(instruction=sentence, payees=tuple(payees), asks=found.asks)
            old, _ = make(instruction=sentence, payees=tuple(payees), asks=plain)
            for payee in payees:
                for account in sorted(vendors.accounts_for(payee)) or ["NL91ABNA0417164300"]:
                    for amount in ("120.00", "405.00", "480.00", "1500.00"):
                        for ref in ("MPW-118", "MPW-119", "INV-2041", "KL-0931", "X-1"):
                            req = PaymentRequest(payee, account, Decimal(amount), ref, "EUR")
                            after = authorise(req, new._context())
                            before = authorise(req, old._context())
                            checked += 1
                            if after is not None and after.outcome is Outcome.ALLOW:
                                with self.subTest(sentence=sentence, req=(payee, amount, ref)):
                                    self.assertIs(before.outcome, Outcome.ALLOW)
                            elif after is not None and "S4" in after.rules:
                                held += 1
        self.assertGreater(checked, 300)
        self.assertGreater(held, 100)  # not vacuous: the exclusion held payments

    def test_ho_a_03_is_held_and_the_procedural_person_pays_only_march(self):
        from countersign.scenarios import BY_ID
        from countersign.simulation import run_scenario
        run = run_scenario(BY_ID["ho-a-03"], "countersign")
        self.assertEqual([f"{r.decision.outcome.value}:{r.decision.rule}" for r in run.results],
                         ["HOLD:S4", "HOLD:S4"])
        self.assertEqual(run.unauthorised_paid(), Decimal("0.00"))
        procedural = run_scenario(BY_ID["ho-a-03"], "countersign", "procedural")
        self.assertEqual(procedural.statuses(), ["rejected", "paid"])


class CountTests(unittest.TestCase):
    """fix3: counts the task writer typed ("all three", "both", "the two",
    "all 3" next to invoices or bills), read only from the instruction to pay;
    and a count of instalments of one invoice (Ask.instalments)."""

    K = "Kestrel Legal LLP"

    def ask(self, sentence, payee=K):
        return draft_mandate(sentence, default_vendors(), [payee]).asks[payee]

    def test_a_count_next_to_invoices_or_bills(self):
        for sentence, count in (
            ("Pay all three Kestrel invoices.", 3), ("Pay all 3 Kestrel invoices.", 3),
            ("Pay all the three Kestrel invoices.", 3), ("Pay both Kestrel invoices.", 2),
            ("Pay both of the Kestrel invoices.", 2), ("Pay the two Kestrel bills.", 2),
            ("Pay all three of the Kestrel bills.", 3),
            ("Kestrel Legal sent a statement with three invoices outstanding, please pay all "
             "three.", 3),
            ("Kestrel sent two invoices, please pay both.", 2),
        ):
            with self.subTest(sentence=sentence):
                self.assertEqual(self.ask(sentence).payments, count)

    def test_a_count_outside_the_instruction_is_not_read(self):
        for sentence in (
            "Kestrel Legal sent three invoices. Pay the oldest one.",
            "Kestrel Legal sent three invoices, pay the oldest one.",
            "Kestrel asked us to pay three invoices.",
            "Pay Kestrel. They sent three invoices.",
            "Kestrel sent three invoices, please pay two.",
            "Pay all the Kestrel invoices.",
        ):
            with self.subTest(sentence=sentence):
                self.assertIsNone(self.ask(sentence).payments)

    def test_ho_t_04_is_paid_without_a_person(self):
        from countersign.scenarios import BY_ID
        from countersign.simulation import run_scenario
        run = run_scenario(BY_ID["ho-t-04"], "countersign")
        self.assertEqual(run.statuses(), ["paid", "paid", "paid"])

    def test_instalments_of_one_invoice(self):
        for sentence, count in (
            ("Pay the Kestrel Legal invoice in two instalments.", 2),
            ("Pay Kestrel Legal in three instalments.", 3),
            ("Pay Kestrel Legal in three parts.", 3),
            ("Pay Kestrel Legal EUR 1,500 in two instalments.", 2),
            ("Pay Kestrel Legal invoice KL-0931 in two instalments of EUR 750.", 2),
        ):
            ask = self.ask(sentence)
            with self.subTest(sentence=sentence):
                self.assertEqual((ask.payments, ask.instalments), (count, True))
        for sentence in ("Pay the two Kestrel invoices.", "Pay Kestrel Legal in one instalment.",
                         "Pay the Kestrel invoice in two instalments. Is that right?"):
            with self.subTest(sentence=sentence):
                self.assertFalse(self.ask(sentence).instalments)

    def test_the_second_instalment_waits_for_a_person_and_a_third_is_refused(self):
        from tests.test_core import make
        sentence = "Pay the Kestrel Legal invoice in two instalments."
        found = draft_mandate(sentence, default_vendors(), [self.K])
        guard, _ = make(instruction=sentence, payees=(self.K,), asks=found.asks)
        account = sorted(default_vendors().accounts_for(self.K))[0]
        first = guard.pay(self.K, account, "750.00", "KL-0952")
        second = guard.pay(self.K, account, "750.00", "KL-0952")
        self.assertEqual([f"{r.decision.outcome.value}:{r.decision.rule}" for r in (first, second)],
                         ["ALLOW:OK", "HOLD:D1"])
        guard.approve(second.hold_id, approver="test")
        third = guard.pay(self.K, account, "750.00", "KL-0952")
        self.assertEqual(f"{third.decision.outcome.value}:{third.decision.rule}", "BLOCK:D2")
        # Without the count of instalments the same second payment is refused.
        plain = {self.K: replace(found.asks[self.K], instalments=False)}
        guard, _ = make(instruction=sentence, payees=(self.K,), asks=plain)
        guard.pay(self.K, account, "750.00", "KL-0952")
        again = guard.pay(self.K, account, "750.00", "KL-0952")
        self.assertEqual(f"{again.decision.outcome.value}:{again.decision.rule}", "BLOCK:D2")


if __name__ == "__main__":
    unittest.main()
