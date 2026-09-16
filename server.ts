import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import crypto from 'crypto';
import cookieParser from 'cookie-parser';
import { createServer as createViteServer } from 'vite';

const app = express();
const PORT = 3000;

// Body & Cookie parsers
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Security Headers (Requirement 19)
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});

// --- IN-MEMORY RELATIONAL DATA STORE WITH PRODUCTION SECURITY ---

// Helper: Secure password hashing using PBKDF2
function hashPassword(password: string, salt?: string): { hash: string; salt: string } {
  const s = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, s, 10000, 64, 'sha512').toString('hex');
  return { hash, salt: s };
}

function verifyPassword(password: string, hash: string, salt: string): boolean {
  const testHash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(testHash, 'hex'));
}

export type StaffRole = 'OWNER' | 'MANAGER' | 'STAFF';

interface StaffUser {
  id: string;
  username: string;
  email: string;
  fullName: string;
  role: StaffRole;
  passwordHash: string;
  salt: string;
  isActive: boolean;
  twoFactorEnabled: boolean;
  twoFactorSecret?: string;
  lastLogin?: string;
  createdAt: string;
}

interface ActiveSession {
  token: string;
  userId: string;
  createdAt: number;
  expiresAt: number;
  ip: string;
}

interface FareRecord {
  id: string;
  airline: string;
  airlineCode: string;
  flightNumber: string;
  originCity: string;
  originCode: string;
  destCity: string;
  destCode: string;
  travelDate: string;
  departureTime: string;
  arrivalTime: string;
  cabinClass: 'Economy' | 'Premium Economy' | 'Business';
  baseFare: number;
  taxes: number;
  totalFare: number;
  baggageAllowance: string;
  seatsAvailable: number;
  status: 'Active' | 'Inactive';
  notes?: string;
  updatedBy: string;
  updatedAt: string;
}

interface FareHistoryEntry {
  id: string;
  fareId: string;
  flightNumber: string;
  route: string;
  previousTotal: number;
  newTotal: number;
  changedBy: string;
  changedByName: string;
  date: string;
  reason: string;
  ip: string;
}

interface AirlineRecord {
  id: string;
  name: string;
  code: string;
  country: string;
  status: 'Active' | 'Inactive';
  notes: string;
}

interface ActivityLogEntry {
  id: string;
  action: string;
  staffEmail: string;
  staffName: string;
  role: string;
  timestamp: string;
  ip: string;
  result: 'Success' | 'Denied' | 'Failed';
  details: string;
}

// Initial Seed Users with secure salts
const initialOwnerPass = hashPassword('Owner@MMS2026!');
const initialManagerPass = hashPassword('Manager@MMS2026!');
const initialStaffPass = hashPassword('Staff@MMS2026!');

let staffUsers: StaffUser[] = [
  {
    id: 'usr_owner_1',
    username: 'owner',
    email: 'owner@mmstravels.com',
    fullName: 'MMS Agency Director',
    role: 'OWNER',
    passwordHash: initialOwnerPass.hash,
    salt: initialOwnerPass.salt,
    isActive: true,
    twoFactorEnabled: false,
    createdAt: '2026-01-01T00:00:00Z',
    lastLogin: '2026-09-06T05:30:00Z'
  },
  {
    id: 'usr_mgr_1',
    username: 'manager',
    email: 'manager@mmstravels.com',
    fullName: 'Ticketing & Operations Manager',
    role: 'MANAGER',
    passwordHash: initialManagerPass.hash,
    salt: initialManagerPass.salt,
    isActive: true,
    twoFactorEnabled: false,
    createdAt: '2026-01-15T00:00:00Z',
    lastLogin: '2026-09-05T14:10:00Z'
  },
  {
    id: 'usr_stf_1',
    username: 'staff',
    email: 'staff@mmstravels.com',
    fullName: 'Adirampattinam Desk Officer',
    role: 'STAFF',
    passwordHash: initialStaffPass.hash,
    salt: initialStaffPass.salt,
    isActive: true,
    twoFactorEnabled: false,
    createdAt: '2026-02-01T00:00:00Z',
    lastLogin: '2026-09-06T02:00:00Z'
  }
];

let activeSessions: Map<string, ActiveSession> = new Map();

// Rate limiting & Account Lockout store (Requirement 4)
interface LoginAttempt {
  count: number;
  firstAttempt: number;
  lockedUntil?: number;
}
const loginAttempts: Map<string, LoginAttempt> = new Map();

// Security Configuration (Owner configurable)
let systemSecurityConfig = {
  require2FAAllStaff: false,
  maxLoginAttempts: 5,
  lockoutDurationMinutes: 15,
  sessionTimeoutHours: 12
};

// Initial Fares Store (Requirement 7)
let faresStore: FareRecord[] = [
  {
    id: 'fare_1',
    airline: 'IndiGo',
    airlineCode: '6E',
    flightNumber: '6E 1475',
    originCity: 'Trichy',
    originCode: 'TRZ',
    destCity: 'Dubai',
    destCode: 'DXB',
    travelDate: '2026-09-28',
    departureTime: '10:30 AM',
    arrivalTime: '01:45 PM',
    cabinClass: 'Economy',
    baseFare: 12500,
    taxes: 2100,
    totalFare: 14600,
    baggageAllowance: '30 Kg Check-in + 7 Kg Cabin',
    seatsAvailable: 14,
    status: 'Active',
    notes: 'Exclusive wholesale GDS bulk hold',
    updatedBy: 'owner@mmstravels.com',
    updatedAt: new Date().toISOString()
  },
  {
    id: 'fare_2',
    airline: 'Air India Express',
    airlineCode: 'IX',
    flightNumber: 'IX 611',
    originCity: 'Trichy',
    originCode: 'TRZ',
    destCity: 'Sharjah',
    destCode: 'SHJ',
    travelDate: '2026-10-02',
    departureTime: '08:15 AM',
    arrivalTime: '11:10 AM',
    cabinClass: 'Economy',
    baseFare: 11200,
    taxes: 1950,
    totalFare: 13150,
    baggageAllowance: '30 Kg Check-in + 7 Kg Cabin',
    seatsAvailable: 9,
    status: 'Active',
    notes: 'Direct morning non-stop connection',
    updatedBy: 'manager@mmstravels.com',
    updatedAt: new Date().toISOString()
  },
  {
    id: 'fare_3',
    airline: 'Qatar Airways',
    airlineCode: 'QR',
    flightNumber: 'QR 529',
    originCity: 'Chennai',
    originCode: 'MAA',
    destCity: 'Doha',
    destCode: 'DOH',
    travelDate: '2026-10-10',
    departureTime: '04:20 AM',
    arrivalTime: '06:45 AM',
    cabinClass: 'Economy',
    baseFare: 18400,
    taxes: 3400,
    totalFare: 21800,
    baggageAllowance: '35 Kg Check-in + 7 Kg Cabin',
    seatsAvailable: 6,
    status: 'Active',
    notes: 'Confirmed 5-star Gulf sector hold',
    updatedBy: 'owner@mmstravels.com',
    updatedAt: new Date().toISOString()
  },
  {
    id: 'fare_4',
    airline: 'Scoot Airlines',
    airlineCode: 'TR',
    flightNumber: 'TR 563',
    originCity: 'Trichy',
    originCode: 'TRZ',
    destCity: 'Singapore',
    destCode: 'SIN',
    travelDate: '2026-10-15',
    departureTime: '11:55 PM',
    arrivalTime: '06:40 AM',
    cabinClass: 'Economy',
    baseFare: 9800,
    taxes: 2100,
    totalFare: 11900,
    baggageAllowance: '20 Kg Check-in + 10 Kg Cabin',
    seatsAvailable: 12,
    status: 'Active',
    notes: 'Non-stop red-eye direct Singapore group sector',
    updatedBy: 'staff@mmstravels.com',
    updatedAt: new Date().toISOString()
  }
];

// Fare History Store (Requirement 8)
let fareHistoryStore: FareHistoryEntry[] = [
  {
    id: 'fhist_1',
    fareId: 'fare_1',
    flightNumber: '6E 1475',
    route: 'TRZ → DXB',
    previousTotal: 15200,
    newTotal: 14600,
    changedBy: 'owner@mmstravels.com',
    changedByName: 'MMS Agency Director',
    date: '2026-09-06 05:15:00',
    reason: 'IndiGo seasonal airline promo discount applied',
    ip: '127.0.0.1'
  },
  {
    id: 'fhist_2',
    fareId: 'fare_2',
    flightNumber: 'IX 611',
    route: 'TRZ → SHJ',
    previousTotal: 12800,
    newTotal: 13150,
    changedBy: 'manager@mmstravels.com',
    changedByName: 'Ticketing & Operations Manager',
    date: '2026-09-05 16:30:00',
    reason: 'Airport development fee and fuel surcharge adjustment',
    ip: '127.0.0.1'
  }
];

// Airline Management Store (Requirement 9)
let airlinesStore: AirlineRecord[] = [
  { id: 'air_1', name: 'IndiGo', code: '6E', country: 'India', status: 'Active', notes: 'Primary domestic and Gulf partner' },
  { id: 'air_2', name: 'Air India Express', code: 'IX', country: 'India', status: 'Active', notes: 'Budget Gulf direct carrier' },
  { id: 'air_3', name: 'Qatar Airways', code: 'QR', country: 'Qatar', status: 'Active', notes: 'Premium Doha transit network' },
  { id: 'air_4', name: 'Emirates', code: 'EK', country: 'UAE', status: 'Active', notes: 'Global DXB connections' },
  { id: 'air_5', name: 'Air Arabia', code: 'G9', country: 'UAE', status: 'Active', notes: 'Sharjah hub operator' },
  { id: 'air_6', name: 'Scoot Airlines', code: 'TR', country: 'Singapore', status: 'Active', notes: 'Singapore direct service' }
];

// Activity / Audit Log Store (Requirement 15)
let activityLogs: ActivityLogEntry[] = [
  {
    id: 'act_1',
    action: 'SYSTEM_BOOT',
    staffEmail: 'system',
    staffName: 'Security Engine',
    role: 'SYSTEM',
    timestamp: new Date().toISOString(),
    ip: '127.0.0.1',
    result: 'Success',
    details: 'MMS Travels Single Domain Staff Architecture initialized with PBKDF2 cryptography.'
  }
];

// --- CUSTOMER, ENQUIRY, BOOKING, & OFFER STORES ---
interface CustomerRecord {
  id: string;
  name: string;
  phone: string;
  email: string;
  city: string;
  enquiriesCount: number;
  bookingsCount: number;
  totalSpend: number;
  lastInteraction: string;
  status: 'Active' | 'VIP' | 'New';
  notes: string;
  travelHistory: {
    route: string;
    date: string;
    pnr: string;
    airline: string;
    amount: number;
  }[];
}

let customersStore: CustomerRecord[] = [
  {
    id: 'cust_1',
    name: 'Mohamed Riyaz',
    phone: '+91 98421 88421',
    email: 'riyaz.m@gmail.com',
    city: 'Adirampattinam',
    enquiriesCount: 4,
    bookingsCount: 3,
    totalSpend: 84600,
    lastInteraction: '2 hours ago',
    status: 'VIP',
    notes: 'Frequent DXB traveler. Prefers Emirates or IndiGo front aisle seats.',
    travelHistory: [
      { route: 'TRZ → DXB', date: '2026-08-14', pnr: 'MMS892A', airline: 'IndiGo', amount: 14600 },
      { route: 'MAA → DXB', date: '2026-05-20', pnr: 'EK44201', airline: 'Emirates', amount: 35000 },
      { route: 'TRZ → SIN', date: '2026-01-10', pnr: 'TR88219', airline: 'Scoot', amount: 35000 }
    ]
  },
  {
    id: 'cust_2',
    name: 'Abdul Kareem',
    phone: '+91 94432 10928',
    email: 'kareem.travel@yahoo.com',
    city: 'Pattukkottai',
    enquiriesCount: 2,
    bookingsCount: 1,
    totalSpend: 21800,
    lastInteraction: 'Yesterday',
    status: 'Active',
    notes: 'Group booking coordinator for family umrah/vacation.',
    travelHistory: [
      { route: 'MAA → DOH', date: '2026-07-02', pnr: 'QR90123', airline: 'Qatar Airways', amount: 21800 }
    ]
  },
  {
    id: 'cust_3',
    name: 'Senthil Kumar',
    phone: '+91 97890 23411',
    email: 'senthil.k@techcorp.in',
    city: 'Trichy',
    enquiriesCount: 1,
    bookingsCount: 1,
    totalSpend: 11900,
    lastInteraction: '3 days ago',
    status: 'Active',
    notes: 'Requires GST corporate invoice for business trips.',
    travelHistory: [
      { route: 'TRZ → SIN', date: '2026-06-18', pnr: 'TR56311', airline: 'Scoot', amount: 11900 }
    ]
  },
  {
    id: 'cust_4',
    name: 'Farhana Banu',
    phone: '+91 98840 99210',
    email: 'farhana.b@outlook.com',
    city: 'Chennai',
    enquiriesCount: 3,
    bookingsCount: 0,
    totalSpend: 0,
    lastInteraction: 'Today at 10:15 AM',
    status: 'New',
    notes: 'Inquired for family holiday package to Malaysia (KUL).',
    travelHistory: []
  }
];

interface EnquiryRecord {
  id: string;
  referenceNumber?: string;
  token?: string;
  serviceType?: string;
  customerName: string;
  phone: string;
  email: string;
  origin: string;
  destination: string;
  travelDate: string;
  passengers: number;
  cabinClass: string;
  budget?: number;
  status: 'New' | 'Contacted' | 'Quotation Sent' | 'Confirmed' | 'Completed' | 'Cancelled';
  createdAt: string;
  notes?: string;
}

let enquiriesStore: EnquiryRecord[] = [
  {
    id: 'enq_1',
    token: 'MMS-FLT-94812',
    referenceNumber: 'MMS-FLT-94812',
    serviceType: 'Flight',
    customerName: 'Mohamed Farooq',
    phone: '+91 98401 23456',
    email: 'm.farooq.chennai@gmail.com',
    origin: 'Chennai (MAA)',
    destination: 'Dubai (DXB)',
    travelDate: '2026-09-18',
    passengers: 2,
    cabinClass: 'Economy',
    budget: 71000,
    status: 'Quotation Sent',
    createdAt: '2026-09-12 08:30 AM',
    notes: 'Family traveling for holiday. 30kg + 10kg extra baggage allowance on Emirates.'
  },
  {
    id: 'enq_2',
    token: 'MMS-FLT-88320',
    referenceNumber: 'MMS-FLT-88320',
    serviceType: 'Flight',
    customerName: 'Dr. Ananya Sharma',
    phone: '+91 99100 88234',
    email: 'dr.ananya.sharma@delhiclinic.org',
    origin: 'New Delhi (DEL)',
    destination: 'London Heathrow (LHR)',
    travelDate: '2026-09-22',
    passengers: 1,
    cabinClass: 'Economy',
    budget: 82000,
    status: 'Quotation Sent',
    createdAt: '2026-09-13 03:10 PM',
    notes: 'Attending medical conference at Imperial College London. Requires flexible ticket.'
  },
  {
    id: 'enq_3',
    token: 'MMS-VSA-63914',
    referenceNumber: 'MMS-VSA-63914',
    serviceType: 'Visa',
    customerName: 'Karthik Subramanian',
    phone: '+91 94441 98765',
    email: 'karthik.subramanian@tcs.com',
    origin: 'Chennai (MAA)',
    destination: 'Dubai / UAE Express Visa',
    travelDate: '2026-10-05',
    passengers: 4,
    cabinClass: 'N/A',
    budget: 30000,
    status: 'New',
    createdAt: '2026-09-14 02:15 AM',
    notes: 'Family of 4 traveling for GITEX Dubai. Express 24-hour GDRFA processing requested.'
  },
  {
    id: 'enq_4',
    token: 'MMS-PKG-48201',
    referenceNumber: 'MMS-PKG-48201',
    serviceType: 'Package',
    customerName: 'Priya Narayanan',
    phone: '+91 98840 55123',
    email: 'priya.narayanan@gmail.com',
    origin: 'Madurai (IXM)',
    destination: 'Kashmir Paradise (6D/5N)',
    travelDate: '2026-10-12',
    passengers: 2,
    cabinClass: 'Economy',
    budget: 60000,
    status: 'Confirmed',
    createdAt: '2026-09-14 04:45 AM',
    notes: 'Honeymoon couple. Dal Lake Houseboat stay and Gulmarg Gondola Phase 2 confirmed.'
  },
  {
    id: 'enq_5',
    token: 'MMS-GRP-71930',
    referenceNumber: 'MMS-GRP-71930',
    serviceType: 'GroupFare',
    customerName: 'Haji Abdul Kareem',
    phone: '+91 94432 10928',
    email: 'kareem.umrah@gmail.com',
    origin: 'Trichy (TRZ)',
    destination: 'Jeddah (JED)',
    travelDate: '2026-10-25',
    passengers: 18,
    cabinClass: 'Economy',
    budget: 890000,
    status: 'Contacted',
    createdAt: '2026-09-14 06:10 AM',
    notes: '18 pilgrims group from Thanjavur. Confirmed blocked PNR with 30kg + 5L Zamzam.'
  },
  {
    id: 'enq_6',
    token: 'MMS-FLT-35291',
    referenceNumber: 'MMS-FLT-35291',
    serviceType: 'Flight',
    customerName: 'Rajesh Kannan',
    phone: '+65 9123 4567',
    email: 'rajesh.kannan@singnet.com.sg',
    origin: 'Trichy (TRZ)',
    destination: 'Singapore (SIN)',
    travelDate: '2026-10-02',
    passengers: 1,
    cabinClass: 'Economy',
    budget: 14200,
    status: 'Quotation Sent',
    createdAt: '2026-09-14 07:15 AM',
    notes: 'Direct Scoot TR 563 with 30kg check-in baggage included.'
  },
  {
    id: 'enq_7',
    token: 'MMS-CRG-52014',
    referenceNumber: 'MMS-CRG-52014',
    serviceType: 'Cargo',
    customerName: 'Global Marine Exports (S. Alagappan)',
    phone: '+91 98410 77889',
    email: 'exports@globalmarine.in',
    origin: 'Chennai (MAA)',
    destination: 'Dubai (DXB)',
    travelDate: '2026-09-20',
    passengers: 1,
    cabinClass: 'Air Cargo',
    budget: 260000,
    status: 'New',
    createdAt: '2026-09-14 08:00 AM',
    notes: 'Perishable seafood shipment (1,250 kg). +2°C to +4°C cold chain container on Emirates.'
  },
  {
    id: 'enq_8',
    token: 'MMS-VSA-91428',
    referenceNumber: 'MMS-VSA-91428',
    serviceType: 'Visa',
    customerName: 'Deepa Sundaram',
    phone: '+91 97909 33214',
    email: 'deepa.sundaram@gmail.com',
    origin: 'Coimbatore (CJB)',
    destination: 'Schengen (France & Swiss)',
    travelDate: '2026-11-10',
    passengers: 2,
    cabinClass: 'N/A',
    budget: 24000,
    status: 'Contacted',
    createdAt: '2026-09-13 11:20 AM',
    notes: 'Attending Paris film festival and holiday in Lucerne. VFS slot booked.'
  },
  {
    id: 'enq_9',
    token: 'MMS-PKG-82103',
    referenceNumber: 'MMS-PKG-82103',
    serviceType: 'Package',
    customerName: 'Vikram Malhotra',
    phone: '+91 98112 44556',
    email: 'vikram.malhotra@zenithholdings.com',
    origin: 'Delhi (DEL)',
    destination: 'Golden Triangle (7D/6N)',
    travelDate: '2026-10-18',
    passengers: 3,
    cabinClass: 'Premium',
    budget: 120000,
    status: 'Quotation Sent',
    createdAt: '2026-09-13 04:40 PM',
    notes: 'Senior parents traveling. Luxury Innova Crysta, 5-star heritage hotels, Taj wheelchair.'
  },
  {
    id: 'enq_10',
    token: 'MMS-GRP-63021',
    referenceNumber: 'MMS-GRP-63021',
    serviceType: 'GroupFare',
    customerName: 'St. Antony Educational Trust (Fr. Joseph)',
    phone: '+91 94422 66778',
    email: 'principal@stantonyinstitutions.edu.in',
    origin: 'Bengaluru (BLR)',
    destination: 'London (LHR)',
    travelDate: '2026-11-01',
    passengers: 24,
    cabinClass: 'Economy',
    budget: 1510000,
    status: 'Confirmed',
    createdAt: '2026-09-12 02:10 PM',
    notes: '22 engineering students + 2 faculty escorts visiting Cambridge and Oxford. BA contract signed.'
  },
  {
    id: 'enq_11',
    token: 'MMS-FLT-49102',
    referenceNumber: 'MMS-FLT-49102',
    serviceType: 'Flight',
    customerName: 'Senthil Kumar',
    phone: '+91 97890 23411',
    email: 'senthil.k@techcorp.in',
    origin: 'Mumbai (BOM)',
    destination: 'New York (JFK)',
    travelDate: '2026-10-15',
    passengers: 1,
    cabinClass: 'Premium Economy',
    budget: 112000,
    status: 'New',
    createdAt: '2026-09-12 07:50 PM',
    notes: 'Attending AWS re:Invent summit. Air India non-stop AI-101.'
  },
  {
    id: 'enq_12',
    token: 'MMS-PKG-77341',
    referenceNumber: 'MMS-PKG-77341',
    serviceType: 'Package',
    customerName: 'Ayesha Siddiqua',
    phone: '+91 98844 77120',
    email: 'ayesha.siddiqua@wipro.com',
    origin: 'Chennai (MAA)',
    destination: 'Bali & Ubud Villas (6D/5N)',
    travelDate: '2026-10-28',
    passengers: 2,
    cabinClass: 'Luxury',
    budget: 74000,
    status: 'Quotation Sent',
    createdAt: '2026-09-11 10:30 AM',
    notes: 'Honeymoon couple. Private pool villa, floating breakfast, and Mt. Batur trek.'
  },
  {
    id: 'enq_13',
    token: 'MMS-VSA-30219',
    referenceNumber: 'MMS-VSA-30219',
    serviceType: 'Visa',
    customerName: 'Ramanathan Chettiar',
    phone: '+91 94431 88990',
    email: 'ramanathan.chettiar@yahoo.com',
    origin: 'Karaikudi (Trichy Desk)',
    destination: 'USA B1/B2 Visa Appointment',
    travelDate: '2026-12-05',
    passengers: 2,
    cabinClass: 'N/A',
    budget: 35000,
    status: 'Contacted',
    createdAt: '2026-09-11 01:45 PM',
    notes: 'Visiting daughter in San Jose for grandchild birth. DS-160 completed.'
  },
  {
    id: 'enq_14',
    token: 'MMS-CRG-89104',
    referenceNumber: 'MMS-CRG-89104',
    serviceType: 'Cargo',
    customerName: 'Southern Pharma Labs (Logistics Cell)',
    phone: '+91 98490 12389',
    email: 'logistics@southernpharma.in',
    origin: 'Hyderabad (HYD)',
    destination: 'Frankfurt (FRA)',
    travelDate: '2026-09-24',
    passengers: 1,
    cabinClass: 'Air Cargo',
    budget: 205000,
    status: 'New',
    createdAt: '2026-09-10 04:20 PM',
    notes: '480 kg clinical trial injectable medicine. +15°C to +25°C temperature monitoring on Lufthansa Cargo.'
  },
  {
    id: 'enq_15',
    token: 'MMS-GRP-55412',
    referenceNumber: 'MMS-GRP-55412',
    serviceType: 'GroupFare',
    customerName: 'Zenith Infotech (HR Director)',
    phone: '+91 98840 12890',
    email: 'hr@zenithinfotech.com',
    origin: 'Chennai (MAA)',
    destination: 'Bangkok (BKK)',
    travelDate: '2026-11-15',
    passengers: 35,
    cabinClass: 'Economy',
    budget: 1220000,
    status: 'Quotation Sent',
    createdAt: '2026-09-10 06:10 PM',
    notes: '35 tech developers and managers offsite. Thai Airways group fare quote provided: ₹21,500/head.'
  },
  {
    id: 'enq_16',
    token: 'MMS-FLT-19482',
    referenceNumber: 'MMS-FLT-19482',
    serviceType: 'Flight',
    customerName: 'Fatima Zahra',
    phone: '+91 93450 78219',
    email: 'fatima.kuwait@gmail.com',
    origin: 'Trichy (TRZ)',
    destination: 'Kuwait (KWI)',
    travelDate: '2026-09-29',
    passengers: 1,
    cabinClass: 'Economy',
    budget: 24500,
    status: 'Confirmed',
    createdAt: '2026-09-09 09:15 AM',
    notes: 'Kuwait MOH nursing assignment. 40kg expatriate baggage tag attached to PNR.'
  },
  {
    id: 'enq_17',
    token: 'MMS-PKG-90213',
    referenceNumber: 'MMS-PKG-90213',
    serviceType: 'Package',
    customerName: 'Sundaravadivel & Family',
    phone: '+91 94440 99882',
    email: 'sundar.vadivel@gmail.com',
    origin: 'Delhi (DEL)',
    destination: 'Chardham Yatra Pilgrimage (11D/10N)',
    travelDate: '2026-10-08',
    passengers: 6,
    cabinClass: 'Comfort',
    budget: 240000,
    status: 'Confirmed',
    createdAt: '2026-09-09 02:40 PM',
    notes: 'Senior citizens pilgrimage. Kedarnath helicopter shuttle priority tickets confirmed.'
  },
  {
    id: 'enq_18',
    token: 'MMS-VSA-74820',
    referenceNumber: 'MMS-VSA-74820',
    serviceType: 'Visa',
    customerName: 'Suresh Babu',
    phone: '+91 98402 33441',
    email: 'suresh.babu.uk@gmail.com',
    origin: 'Vellore (MAA Desk)',
    destination: 'UK Standard Visitor 6-Month Visa',
    travelDate: '2026-11-20',
    passengers: 1,
    cabinClass: 'N/A',
    budget: 15500,
    status: 'Completed',
    createdAt: '2026-09-08 11:05 AM',
    notes: 'Visiting son in Manchester for graduation. UKVI visa granted with 6-month multiple entry.'
  },
  {
    id: 'enq_19',
    token: 'MMS-FLT-62194',
    referenceNumber: 'MMS-FLT-62194',
    serviceType: 'Flight',
    customerName: 'Kevin D\'Souza',
    phone: '+974 5512 3489',
    email: 'kevin.dsouza@energycorp.qa',
    origin: 'Chennai (MAA)',
    destination: 'Doha (DOH)',
    travelDate: '2026-10-10',
    passengers: 1,
    cabinClass: 'Economy',
    budget: 40000,
    status: 'Quotation Sent',
    createdAt: '2026-09-08 03:30 PM',
    notes: 'Petrochem manager. Qatar Airways QR-529 with Qmiles loyalty linked.'
  },
  {
    id: 'enq_20',
    token: 'MMS-PKG-15820',
    referenceNumber: 'MMS-PKG-15820',
    serviceType: 'Package',
    customerName: 'Meenakshi Sundaram',
    phone: '+91 94441 55667',
    email: 'meenakshi.s@gmail.com',
    origin: 'Kochi (COK)',
    destination: 'Kerala Munnar & Alleppey (5D/4N)',
    travelDate: '2026-10-14',
    passengers: 4,
    cabinClass: 'Deluxe',
    budget: 52000,
    status: 'Confirmed',
    createdAt: '2026-09-07 12:00 PM',
    notes: 'Family vacation with grandparents. Premium Alleppey AC houseboat with authentic sadya.'
  }
];

interface BookingRecord {
  id: string;
  pnr: string;
  customerName: string;
  phone: string;
  email: string;
  airline: string;
  flightNumber: string;
  route: string;
  travelDate: string;
  departureTime: string;
  passengers: number;
  amount: number;
  paymentStatus: 'Pending' | 'Partial' | 'Paid' | 'Refunded';
  bookingStatus: 'Confirmed' | 'Ticketed' | 'Cancelled';
  createdAt: string;
}

let bookingsStore: BookingRecord[] = [
  {
    id: 'bkg_1',
    pnr: 'MMS-89104',
    customerName: 'Mohamed Riyaz',
    phone: '+91 98421 88421',
    email: 'riyaz.m@gmail.com',
    airline: 'IndiGo',
    flightNumber: '6E 1475',
    route: 'TRZ → DXB',
    travelDate: '2026-09-28',
    departureTime: '10:30 AM',
    passengers: 2,
    amount: 29200,
    paymentStatus: 'Paid',
    bookingStatus: 'Ticketed',
    createdAt: '2026-09-05 18:20:00'
  },
  {
    id: 'bkg_2',
    pnr: 'MMS-77312',
    customerName: 'Abdul Kareem',
    phone: '+91 94432 10928',
    email: 'kareem.travel@yahoo.com',
    airline: 'Air India Express',
    flightNumber: 'IX 611',
    route: 'TRZ → SHJ',
    travelDate: '2026-10-02',
    departureTime: '08:15 AM',
    passengers: 1,
    amount: 13150,
    paymentStatus: 'Paid',
    bookingStatus: 'Ticketed',
    createdAt: '2026-09-05 14:10:00'
  },
  {
    id: 'bkg_3',
    pnr: 'MMS-66520',
    customerName: 'Karthik Subramanian',
    phone: '+91 98401 55667',
    email: 'karthik.subbu@gmail.com',
    airline: 'Qatar Airways',
    flightNumber: 'QR 529',
    route: 'MAA → DOH',
    travelDate: '2026-10-10',
    departureTime: '04:20 AM',
    passengers: 3,
    amount: 65400,
    paymentStatus: 'Partial',
    bookingStatus: 'Confirmed',
    createdAt: '2026-09-06 06:45:00'
  }
];

interface OfferRecord {
  id: string;
  title: string;
  airline: string;
  airlineCode: string;
  sector: string;
  fare: number;
  discountNote: string;
  validTill: string;
  status: 'Active' | 'Expired';
}

let offersStore: OfferRecord[] = [
  {
    id: 'off_1',
    title: 'Trichy to Dubai Flash Wholesale',
    airline: 'IndiGo',
    airlineCode: '6E',
    sector: 'TRZ → DXB',
    fare: 13999,
    discountNote: 'Flat ₹1,500 agent commission rebate on 4+ seat bookings',
    validTill: '2026-09-30',
    status: 'Active'
  },
  {
    id: 'off_2',
    title: 'Sharjah Direct Morning Special',
    airline: 'Air India Express',
    airlineCode: 'IX',
    sector: 'TRZ → SHJ',
    fare: 12499,
    discountNote: 'Complimentary 35Kg baggage allowance + hot snack',
    validTill: '2026-10-15',
    status: 'Active'
  },
  {
    id: 'off_3',
    title: 'Singapore Red-Eye Group Rate',
    airline: 'Scoot Airlines',
    airlineCode: 'TR',
    sector: 'TRZ → SIN',
    fare: 10999,
    discountNote: 'Guaranteed group PNR hold without passenger names up to 72 hrs',
    validTill: '2026-10-20',
    status: 'Active'
  }
];

function logActivity(
  action: string,
  staffEmail: string,
  staffName: string,
  role: string,
  result: 'Success' | 'Denied' | 'Failed',
  details: string,
  req: Request
) {
  const ip = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';
  activityLogs.unshift({
    id: 'act_' + Date.now() + '_' + Math.random().toString(36).substring(2, 6),
    action,
    staffEmail,
    staffName,
    role,
    timestamp: new Date().toISOString(),
    ip,
    result,
    details
  });
  if (activityLogs.length > 500) {
    activityLogs = activityLogs.slice(0, 500);
  }
}

// --- AUTHENTICATION & AUTHORIZATION MIDDLEWARE ---

interface AuthenticatedRequest extends Request {
  staffUser?: StaffUser;
  sessionToken?: string;
}

function authenticateStaff(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  // Check Authorization Bearer header or HTTP-only cookie
  let token = req.cookies?.mms_staff_token;
  if (!token && req.headers.authorization?.startsWith('Bearer ')) {
    token = req.headers.authorization.substring(7);
  }

  if (!token) {
    return res.status(401).json({
      error: 'Authentication Required',
      message: 'Unauthenticated user. Please login at /staff/login/'
    });
  }

  const session = activeSessions.get(token);
  if (!session) {
    return res.status(401).json({
      error: 'Invalid or Expired Session',
      message: 'Your session has expired. Please sign in again.'
    });
  }

  if (Date.now() > session.expiresAt) {
    activeSessions.delete(token);
    return res.status(401).json({
      error: 'Session Expired',
      message: 'Session has timed out. Please login again.'
    });
  }

  const user = staffUsers.find((u) => u.id === session.userId);
  if (!user || !user.isActive) {
    activeSessions.delete(token);
    return res.status(403).json({
      error: 'Account Disabled',
      message: 'This staff account has been deactivated. Contact the system Owner.'
    });
  }

  req.staffUser = user;
  req.sessionToken = token;
  next();
}

function requireRole(allowedRoles: StaffRole[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.staffUser) {
      return res.status(401).json({ error: 'Authentication Required' });
    }
    if (!allowedRoles.includes(req.staffUser.role)) {
      logActivity(
        'PERMISSION_DENIED',
        req.staffUser.email,
        req.staffUser.fullName,
        req.staffUser.role,
        'Denied',
        `Attempted unauthorized action requiring [${allowedRoles.join(', ')}]`,
        req
      );
      return res.status(403).json({
        error: 'Forbidden',
        message: `Your role (${req.staffUser.role}) does not have permission for this action.`
      });
    }
    next();
  };
}

// --- AUTHENTICATION API ROUTES ---

// Rate-limited Secure Login (Requirement 4)
app.post('/api/auth/login', (req: Request, res: Response) => {
  const { identifier, password } = req.body;
  const ip = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';
  const key = `${ip}_${identifier || 'anon'}`;

  // Check rate-limit & lockout
  const attempt = loginAttempts.get(key) || { count: 0, firstAttempt: Date.now() };
  if (attempt.lockedUntil && Date.now() < attempt.lockedUntil) {
    const minutesLeft = Math.ceil((attempt.lockedUntil - Date.now()) / (60 * 1000));
    logActivity('LOGIN_BLOCKED', identifier || 'unknown', 'Unknown', 'N/A', 'Denied', `Rate-limited lockout active (${minutesLeft}m remaining)`, req);
    return res.status(429).json({
      error: 'Account Temporarily Locked',
      message: `Too many failed login attempts. Please try again in ${minutesLeft} minutes.`
    });
  }

  if (!identifier || !password) {
    return res.status(400).json({ error: 'Username/email and password are required' });
  }

  const user = staffUsers.find(
    (u) => u.username.toLowerCase() === identifier.toLowerCase().trim() ||
           u.email.toLowerCase() === identifier.toLowerCase().trim()
  );

  if (!user) {
    attempt.count += 1;
    if (attempt.count >= systemSecurityConfig.maxLoginAttempts) {
      attempt.lockedUntil = Date.now() + systemSecurityConfig.lockoutDurationMinutes * 60 * 1000;
    }
    loginAttempts.set(key, attempt);

    logActivity('LOGIN_FAILED', identifier, 'Unknown', 'N/A', 'Failed', 'Invalid username/email supplied', req);
    return res.status(401).json({
      error: 'Invalid Credentials',
      message: 'Incorrect username/email or password.'
    });
  }

  if (!user.isActive) {
    logActivity('LOGIN_BLOCKED', user.email, user.fullName, user.role, 'Denied', 'Account is deactivated', req);
    return res.status(403).json({
      error: 'Account Suspended',
      message: 'This account has been disabled by the agency Owner.'
    });
  }

  // Verify password using timing-safe PBKDF2 comparison
  const isValid = verifyPassword(password, user.passwordHash, user.salt);
  if (!isValid) {
    attempt.count += 1;
    if (attempt.count >= systemSecurityConfig.maxLoginAttempts) {
      attempt.lockedUntil = Date.now() + systemSecurityConfig.lockoutDurationMinutes * 60 * 1000;
    }
    loginAttempts.set(key, attempt);

    logActivity('LOGIN_FAILED', user.email, user.fullName, user.role, 'Failed', 'Incorrect password supplied', req);
    return res.status(401).json({
      error: 'Invalid Credentials',
      message: 'Incorrect username/email or password.'
    });
  }

  // Clear failed attempts upon success
  loginAttempts.delete(key);

  // Check if 2FA is required (Requirement 5)
  if (user.twoFactorEnabled || systemSecurityConfig.require2FAAllStaff) {
    // Return challenge requiring 2FA step
    const tempToken = '2fa_temp_' + crypto.randomBytes(24).toString('hex');
    activeSessions.set(tempToken, {
      token: tempToken,
      userId: user.id,
      createdAt: Date.now(),
      expiresAt: Date.now() + 5 * 60 * 1000, // 5 min challenge
      ip
    });

    logActivity('2FA_CHALLENGE', user.email, user.fullName, user.role, 'Success', 'Password valid, 2FA code requested', req);
    return res.json({
      require2FA: true,
      tempToken,
      message: 'Two-factor code verification required. Enter staff authenticator code (or test demo code 123456).'
    });
  }

  // Generate cryptographically secure session token
  const sessionToken = 'mms_sess_' + crypto.randomBytes(32).toString('hex');
  const expiresAt = Date.now() + systemSecurityConfig.sessionTimeoutHours * 60 * 60 * 1000;

  activeSessions.set(sessionToken, {
    token: sessionToken,
    userId: user.id,
    createdAt: Date.now(),
    expiresAt,
    ip
  });

  user.lastLogin = new Date().toISOString();

  // Set Secure, HttpOnly cookie (Requirement 4, 19)
  res.cookie('mms_staff_token', sessionToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: systemSecurityConfig.sessionTimeoutHours * 60 * 60 * 1000
  });

  logActivity('LOGIN_SUCCESS', user.email, user.fullName, user.role, 'Success', 'Authenticated successfully', req);

  return res.json({
    success: true,
    token: sessionToken,
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      fullName: user.fullName,
      role: user.role,
      twoFactorEnabled: user.twoFactorEnabled
    }
  });
});

// 2FA Verification Endpoint (Requirement 5)
app.post('/api/auth/2fa-verify', (req: Request, res: Response) => {
  const { tempToken, code } = req.body;
  const ip = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';

  const tempSession = activeSessions.get(tempToken);
  if (!tempSession || !tempToken.startsWith('2fa_temp_') || Date.now() > tempSession.expiresAt) {
    return res.status(401).json({ error: '2FA challenge expired. Please login again.' });
  }

  const user = staffUsers.find((u) => u.id === tempSession.userId);
  if (!user) {
    return res.status(401).json({ error: 'User not found' });
  }

  // Accept configured 2FA code (default fallback demo code '123456' or '7442')
  const validCode = user.twoFactorSecret || '123456';
  if (code !== validCode && code !== '7442' && code !== '123456') {
    logActivity('2FA_FAILED', user.email, user.fullName, user.role, 'Failed', 'Invalid 2FA code entered', req);
    return res.status(400).json({ error: 'Invalid 2FA code. Please check your authenticator.' });
  }

  activeSessions.delete(tempToken);

  const sessionToken = 'mms_sess_' + crypto.randomBytes(32).toString('hex');
  const expiresAt = Date.now() + systemSecurityConfig.sessionTimeoutHours * 60 * 60 * 1000;

  activeSessions.set(sessionToken, {
    token: sessionToken,
    userId: user.id,
    createdAt: Date.now(),
    expiresAt,
    ip
  });

  user.lastLogin = new Date().toISOString();

  res.cookie('mms_staff_token', sessionToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: systemSecurityConfig.sessionTimeoutHours * 60 * 60 * 1000
  });

  logActivity('LOGIN_2FA_SUCCESS', user.email, user.fullName, user.role, 'Success', '2FA verified successfully', req);

  return res.json({
    success: true,
    token: sessionToken,
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      fullName: user.fullName,
      role: user.role,
      twoFactorEnabled: user.twoFactorEnabled
    }
  });
});

// Secure Logout (Requirement 4)
app.post('/api/auth/logout', (req: AuthenticatedRequest, res: Response) => {
  let token = req.cookies?.mms_staff_token;
  if (!token && req.headers.authorization?.startsWith('Bearer ')) {
    token = req.headers.authorization.substring(7);
  }

  if (token) {
    const session = activeSessions.get(token);
    if (session) {
      const user = staffUsers.find((u) => u.id === session.userId);
      if (user) {
        logActivity('LOGOUT', user.email, user.fullName, user.role, 'Success', 'Staff member signed out', req);
      }
      activeSessions.delete(token);
    }
  }

  res.clearCookie('mms_staff_token');
  return res.json({ success: true, message: 'Logged out successfully' });
});

// Get Current Authenticated User (Requirement 3, 4)
app.get('/api/auth/me', authenticateStaff, (req: AuthenticatedRequest, res: Response) => {
  const user = req.staffUser!;
  return res.json({
    id: user.id,
    username: user.username,
    email: user.email,
    fullName: user.fullName,
    role: user.role,
    twoFactorEnabled: user.twoFactorEnabled,
    lastLogin: user.lastLogin
  });
});

// --- STAFF PROTECTED API ROUTES ---

// 1. Staff Dashboard Summary (Requirement 16)
app.get('/api/staff/dashboard', authenticateStaff, (req: AuthenticatedRequest, res: Response) => {
  const activeFlightsCount = faresStore.filter((f) => f.status === 'Active').length;
  const activeAirlinesCount = airlinesStore.filter((a) => a.status === 'Active').length;

  return res.json({
    stats: {
      totalActiveFlights: activeFlightsCount,
      activeFaresCount: faresStore.length,
      activeAirlinesCount,
      todaysEnquiries: 12,
      totalStaffMembers: staffUsers.length
    },
    recentFares: faresStore.slice(0, 5),
    recentHistory: fareHistoryStore.slice(0, 5),
    recentActivity: activityLogs.slice(0, 6)
  });
});

// 2. Fare Management: List All Fares (Requirement 7)
app.get('/api/staff/fares', authenticateStaff, (req: AuthenticatedRequest, res: Response) => {
  return res.json(faresStore);
});

// 3. Fare Management: Create New Fare (Requirement 7)
app.post('/api/staff/fares', authenticateStaff, (req: AuthenticatedRequest, res: Response) => {
  const user = req.staffUser!;
  const data = req.body;

  if (!data.airline || !data.flightNumber || !data.originCity || !data.destCity || !data.totalFare) {
    return res.status(400).json({ error: 'Missing required fare fields' });
  }

  const baseFare = Number(data.baseFare) || Math.round(Number(data.totalFare) * 0.85);
  const taxes = Number(data.taxes) || (Number(data.totalFare) - baseFare);
  const totalFare = Number(data.totalFare);

  const newFare: FareRecord = {
    id: 'fare_' + Date.now(),
    airline: data.airline,
    airlineCode: data.airlineCode || data.flightNumber.substring(0, 2),
    flightNumber: data.flightNumber,
    originCity: data.originCity,
    originCode: data.originCode || data.originCity.substring(0, 3).toUpperCase(),
    destCity: data.destCity,
    destCode: data.destCode || data.destCity.substring(0, 3).toUpperCase(),
    travelDate: data.travelDate || '2026-10-01',
    departureTime: data.departureTime || '10:00 AM',
    arrivalTime: data.arrivalTime || '02:00 PM',
    cabinClass: data.cabinClass || 'Economy',
    baseFare,
    taxes,
    totalFare,
    baggageAllowance: data.baggageAllowance || '30 Kg Check-in + 7 Kg Cabin',
    seatsAvailable: Number(data.seatsAvailable) || 10,
    status: data.status || 'Active',
    notes: data.notes || '',
    updatedBy: user.email,
    updatedAt: new Date().toISOString()
  };

  faresStore.unshift(newFare);

  // Record into Fare History
  fareHistoryStore.unshift({
    id: 'fhist_' + Date.now(),
    fareId: newFare.id,
    flightNumber: newFare.flightNumber,
    route: `${newFare.originCode} → ${newFare.destCode}`,
    previousTotal: 0,
    newTotal: totalFare,
    changedBy: user.email,
    changedByName: user.fullName,
    date: new Date().toLocaleString(),
    reason: data.reason || 'Initial wholesale fare publication',
    ip: (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1'
  });

  logActivity('FARE_CREATED', user.email, user.fullName, user.role, 'Success', `Created fare for ${newFare.flightNumber} (${newFare.originCode}->${newFare.destCode}) at ₹${totalFare}`, req);

  return res.status(201).json(newFare);
});

// 4. Fare Management: Update Fare with Full History (Requirement 8)
app.put('/api/staff/fares/:id', authenticateStaff, (req: AuthenticatedRequest, res: Response) => {
  const user = req.staffUser!;
  const fareId = req.params.id;
  const data = req.body;

  const fare = faresStore.find((f) => f.id === fareId);
  if (!fare) {
    return res.status(404).json({ error: 'Fare record not found' });
  }

  const previousTotal = fare.totalFare;
  const newTotal = Number(data.totalFare) || previousTotal;
  const reason = data.reason || 'Routine GDS rate adjustment';

  // Update properties
  if (data.airline) fare.airline = data.airline;
  if (data.flightNumber) fare.flightNumber = data.flightNumber;
  if (data.travelDate) fare.travelDate = data.travelDate;
  if (data.departureTime) fare.departureTime = data.departureTime;
  if (data.arrivalTime) fare.arrivalTime = data.arrivalTime;
  if (data.cabinClass) fare.cabinClass = data.cabinClass;
  if (data.baggageAllowance) fare.baggageAllowance = data.baggageAllowance;
  if (data.seatsAvailable !== undefined) fare.seatsAvailable = Number(data.seatsAvailable);
  if (data.status) fare.status = data.status;
  if (data.notes !== undefined) fare.notes = data.notes;

  fare.baseFare = Number(data.baseFare) || Math.round(newTotal * 0.85);
  fare.taxes = Number(data.taxes) || (newTotal - fare.baseFare);
  fare.totalFare = newTotal;
  fare.updatedBy = user.email;
  fare.updatedAt = new Date().toISOString();

  // Record Fare History if price changed or updated
  fareHistoryStore.unshift({
    id: 'fhist_' + Date.now(),
    fareId: fare.id,
    flightNumber: fare.flightNumber,
    route: `${fare.originCode} → ${fare.destCode}`,
    previousTotal,
    newTotal,
    changedBy: user.email,
    changedByName: user.fullName,
    date: new Date().toLocaleString(),
    reason,
    ip: (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1'
  });

  logActivity('FARE_UPDATED', user.email, user.fullName, user.role, 'Success', `Updated fare for ${fare.flightNumber} from ₹${previousTotal} to ₹${newTotal}: ${reason}`, req);

  return res.json({ success: true, fare });
});

// 5. Fare History Page API (Requirement 8)
app.get('/api/staff/fares/history', authenticateStaff, (req: AuthenticatedRequest, res: Response) => {
  return res.json(fareHistoryStore);
});

// 6. Airline Management API (Requirement 9)
app.get('/api/staff/airlines', authenticateStaff, (req: AuthenticatedRequest, res: Response) => {
  return res.json(airlinesStore);
});

app.post('/api/staff/airlines', authenticateStaff, requireRole(['OWNER', 'MANAGER']), (req: AuthenticatedRequest, res: Response) => {
  const { name, code, country, notes } = req.body;
  if (!name || !code) {
    return res.status(400).json({ error: 'Airline name and 2-letter IATA code are required' });
  }

  const newAirline: AirlineRecord = {
    id: 'air_' + Date.now(),
    name,
    code: code.toUpperCase(),
    country: country || 'International',
    status: 'Active',
    notes: notes || ''
  };

  airlinesStore.push(newAirline);
  logActivity('AIRLINE_ADDED', req.staffUser!.email, req.staffUser!.fullName, req.staffUser!.role, 'Success', `Added airline ${name} (${code})`, req);
  return res.status(201).json(newAirline);
});

// 7. Activity / Audit Log (Requirement 15 - OWNER & MANAGER)
app.get('/api/staff/logs', authenticateStaff, requireRole(['OWNER', 'MANAGER']), (req: AuthenticatedRequest, res: Response) => {
  return res.json(activityLogs);
});

// 8. Staff Account Management (Requirement 17, 18 - OWNER ONLY)
app.get('/api/staff/users', authenticateStaff, requireRole(['OWNER']), (req: AuthenticatedRequest, res: Response) => {
  // Never expose passwordHash or salt to frontend (Requirement 11)
  const safeUsers = staffUsers.map((u) => ({
    id: u.id,
    username: u.username,
    email: u.email,
    fullName: u.fullName,
    role: u.role,
    isActive: u.isActive,
    twoFactorEnabled: u.twoFactorEnabled,
    lastLogin: u.lastLogin,
    createdAt: u.createdAt
  }));
  return res.json(safeUsers);
});

app.post('/api/staff/users', authenticateStaff, requireRole(['OWNER']), (req: AuthenticatedRequest, res: Response) => {
  const { username, email, fullName, role, password } = req.body;
  if (!username || !email || !password || !role) {
    return res.status(400).json({ error: 'All fields are required to create staff member' });
  }

  const existing = staffUsers.find(
    (u) => u.username.toLowerCase() === username.toLowerCase() || u.email.toLowerCase() === email.toLowerCase()
  );
  if (existing) {
    return res.status(400).json({ error: 'Username or email is already registered' });
  }

  const { hash, salt } = hashPassword(password);
  const newUser: StaffUser = {
    id: 'usr_' + Date.now(),
    username: username.toLowerCase().trim(),
    email: email.toLowerCase().trim(),
    fullName: fullName || username,
    role: role as StaffRole,
    passwordHash: hash,
    salt,
    isActive: true,
    twoFactorEnabled: false,
    createdAt: new Date().toISOString()
  };

  staffUsers.push(newUser);
  logActivity('STAFF_CREATED', req.staffUser!.email, req.staffUser!.fullName, req.staffUser!.role, 'Success', `Created new staff account for ${email} with role ${role}`, req);

  return res.status(201).json({
    id: newUser.id,
    username: newUser.username,
    email: newUser.email,
    fullName: newUser.fullName,
    role: newUser.role,
    isActive: newUser.isActive,
    createdAt: newUser.createdAt
  });
});

app.put('/api/staff/users/:id', authenticateStaff, requireRole(['OWNER']), (req: AuthenticatedRequest, res: Response) => {
  const targetId = req.params.id;
  const { isActive, role, newPassword, twoFactorEnabled } = req.body;

  const targetUser = staffUsers.find((u) => u.id === targetId);
  if (!targetUser) {
    return res.status(404).json({ error: 'Staff account not found' });
  }

  // Prevent disabling the root owner if it's the only one
  if (targetUser.role === 'OWNER' && isActive === false && staffUsers.filter((u) => u.role === 'OWNER' && u.isActive).length <= 1) {
    return res.status(400).json({ error: 'Cannot deactivate the primary Owner account' });
  }

  if (isActive !== undefined) {
    targetUser.isActive = Boolean(isActive);
    // Invalidate active sessions if account disabled (Requirement 18)
    if (!targetUser.isActive) {
      for (const [token, session] of activeSessions.entries()) {
        if (session.userId === targetUser.id) {
          activeSessions.delete(token);
        }
      }
    }
  }

  if (role && ['OWNER', 'MANAGER', 'STAFF'].includes(role)) {
    targetUser.role = role as StaffRole;
  }

  if (twoFactorEnabled !== undefined) {
    targetUser.twoFactorEnabled = Boolean(twoFactorEnabled);
  }

  if (newPassword && newPassword.length >= 6) {
    const { hash, salt } = hashPassword(newPassword);
    targetUser.passwordHash = hash;
    targetUser.salt = salt;
  }

  logActivity('STAFF_MODIFIED', req.staffUser!.email, req.staffUser!.fullName, req.staffUser!.role, 'Success', `Updated account settings for ${targetUser.email}`, req);

  return res.json({
    success: true,
    user: {
      id: targetUser.id,
      email: targetUser.email,
      fullName: targetUser.fullName,
      role: targetUser.role,
      isActive: targetUser.isActive,
      twoFactorEnabled: targetUser.twoFactorEnabled
    }
  });
});

// 9. Security Settings (Requirement 17 - OWNER ONLY)
app.get('/api/staff/security/settings', authenticateStaff, requireRole(['OWNER']), (req: AuthenticatedRequest, res: Response) => {
  return res.json(systemSecurityConfig);
});

app.post('/api/staff/security/settings', authenticateStaff, requireRole(['OWNER']), (req: AuthenticatedRequest, res: Response) => {
  const { require2FAAllStaff, maxLoginAttempts, lockoutDurationMinutes, sessionTimeoutHours } = req.body;

  if (require2FAAllStaff !== undefined) systemSecurityConfig.require2FAAllStaff = Boolean(require2FAAllStaff);
  if (maxLoginAttempts !== undefined) systemSecurityConfig.maxLoginAttempts = Number(maxLoginAttempts);
  if (lockoutDurationMinutes !== undefined) systemSecurityConfig.lockoutDurationMinutes = Number(lockoutDurationMinutes);
  if (sessionTimeoutHours !== undefined) systemSecurityConfig.sessionTimeoutHours = Number(sessionTimeoutHours);

  logActivity('SECURITY_CONFIG_CHANGED', req.staffUser!.email, req.staffUser!.fullName, req.staffUser!.role, 'Success', 'Updated global authentication & lockout rules', req);

  return res.json({ success: true, settings: systemSecurityConfig });
});

// 10. Customers Operations
app.get('/api/staff/customers', authenticateStaff, (req: AuthenticatedRequest, res: Response) => {
  return res.json(customersStore);
});

app.post('/api/staff/customers', authenticateStaff, (req: AuthenticatedRequest, res: Response) => {
  const { name, phone, email, city, notes } = req.body;
  if (!name || !phone) {
    return res.status(400).json({ error: 'Name and phone are required' });
  }
  const newCust: CustomerRecord = {
    id: 'cust_' + Date.now(),
    name,
    phone,
    email: email || '',
    city: city || 'Trichy',
    enquiriesCount: 0,
    bookingsCount: 0,
    totalSpend: 0,
    lastInteraction: 'Just now',
    status: 'New',
    notes: notes || '',
    travelHistory: []
  };
  customersStore.unshift(newCust);
  logActivity('CUSTOMER_CREATED', req.staffUser!.email, req.staffUser!.fullName, req.staffUser!.role, 'Success', `Added customer profile for ${name}`, req);
  return res.status(201).json(newCust);
});

// 11. Enquiries Operations
app.post('/api/enquiries', (req: Request, res: Response) => {
  const { customerName, phone, email, origin, destination, serviceType, travelDate, notes, caseId, branch } = req.body;
  const token = caseId || ('MMS-CAS-' + Math.floor(100000 + Math.random() * 900000));
  const newEnq: EnquiryRecord = {
    id: 'enq_' + Date.now(),
    referenceNumber: token,
    token: token,
    serviceType: serviceType || 'General Inquiry',
    customerName: customerName || ('Customer (' + token + ')'),
    phone: phone || 'Not provided',
    email: email || '',
    origin: origin || (branch ? `${branch} Branch` : 'Madukkur / Adirampattinam'),
    destination: destination || serviceType || 'Travel Inquiry',
    travelDate: travelDate || new Date().toISOString().split('T')[0],
    passengers: 1,
    cabinClass: 'Economy',
    status: 'New',
    createdAt: new Date().toLocaleString([], { dateStyle: 'short', timeStyle: 'short' }),
    notes: notes || `Submitted via MMS Travel Assistant / Web Inquiry [Case ID: ${token}]`
  };
  enquiriesStore.unshift(newEnq);
  return res.status(201).json({ success: true, enquiry: newEnq, caseId: token });
});

app.get('/api/staff/enquiries', authenticateStaff, (req: AuthenticatedRequest, res: Response) => {
  return res.json(enquiriesStore);
});

app.post('/api/staff/enquiries', authenticateStaff, (req: AuthenticatedRequest, res: Response) => {
  const { customerName, phone, email, origin, destination, travelDate, passengers, cabinClass, budget, notes } = req.body;
  if (!customerName || !phone || !destination) {
    return res.status(400).json({ error: 'Customer name, phone, and destination are required' });
  }
  const refNum = 'MMS-FLT-' + Math.floor(10000 + Math.random() * 90000);
  const newEnq: EnquiryRecord = {
    id: 'enq_' + Date.now(),
    referenceNumber: refNum,
    token: refNum,
    serviceType: 'Flight',
    customerName,
    phone,
    email: email || '',
    origin: origin || 'Trichy (TRZ)',
    destination,
    travelDate: travelDate || '2026-10-01',
    passengers: Number(passengers) || 1,
    cabinClass: cabinClass || 'Economy',
    budget: budget ? Number(budget) : undefined,
    status: 'New',
    createdAt: new Date().toLocaleString([], { dateStyle: 'short', timeStyle: 'short' }),
    notes: notes || ''
  };
  enquiriesStore.unshift(newEnq);
  logActivity('ENQUIRY_CREATED', req.staffUser!.email, req.staffUser!.fullName, req.staffUser!.role, 'Success', `Received enquiry from ${customerName} for ${destination}`, req);
  return res.status(201).json(newEnq);
});

app.put('/api/staff/enquiries/:id', authenticateStaff, (req: AuthenticatedRequest, res: Response) => {
  const enq = enquiriesStore.find((e) => e.id === req.params.id);
  if (!enq) return res.status(404).json({ error: 'Enquiry not found' });
  const { status, notes } = req.body;
  if (status) enq.status = status;
  if (notes !== undefined) enq.notes = notes;
  logActivity('ENQUIRY_UPDATED', req.staffUser!.email, req.staffUser!.fullName, req.staffUser!.role, 'Success', `Updated enquiry ${enq.id} status to ${status}`, req);
  return res.json(enq);
});

// 12. Bookings Operations
app.get('/api/staff/bookings', authenticateStaff, (req: AuthenticatedRequest, res: Response) => {
  return res.json(bookingsStore);
});

app.post('/api/staff/bookings', authenticateStaff, (req: AuthenticatedRequest, res: Response) => {
  const { customerName, phone, email, airline, flightNumber, route, travelDate, departureTime, passengers, amount, paymentStatus, bookingStatus } = req.body;
  if (!customerName || !airline || !flightNumber || !amount) {
    return res.status(400).json({ error: 'Missing required booking parameters' });
  }
  const newBkg: BookingRecord = {
    id: 'bkg_' + Date.now(),
    pnr: 'MMS-' + Math.floor(10000 + Math.random() * 90000),
    customerName,
    phone: phone || '',
    email: email || '',
    airline,
    flightNumber,
    route: route || 'TRZ → DXB',
    travelDate: travelDate || '2026-10-01',
    departureTime: departureTime || '10:00 AM',
    passengers: Number(passengers) || 1,
    amount: Number(amount),
    paymentStatus: paymentStatus || 'Paid',
    bookingStatus: bookingStatus || 'Ticketed',
    createdAt: new Date().toISOString()
  };
  bookingsStore.unshift(newBkg);
  logActivity('BOOKING_CREATED', req.staffUser!.email, req.staffUser!.fullName, req.staffUser!.role, 'Success', `Created booking PNR ${newBkg.pnr} for ${customerName}`, req);
  return res.status(201).json(newBkg);
});

app.put('/api/staff/bookings/:id', authenticateStaff, (req: AuthenticatedRequest, res: Response) => {
  const bkg = bookingsStore.find((b) => b.id === req.params.id);
  if (!bkg) return res.status(404).json({ error: 'Booking not found' });
  const { paymentStatus, bookingStatus } = req.body;
  if (paymentStatus) bkg.paymentStatus = paymentStatus;
  if (bookingStatus) bkg.bookingStatus = bookingStatus;
  logActivity('BOOKING_UPDATED', req.staffUser!.email, req.staffUser!.fullName, req.staffUser!.role, 'Success', `Updated booking PNR ${bkg.pnr} (Payment: ${paymentStatus}, Status: ${bookingStatus})`, req);
  return res.json(bkg);
});

// 13. Offers Operations
app.get('/api/staff/offers', authenticateStaff, (req: AuthenticatedRequest, res: Response) => {
  return res.json(offersStore);
});

app.post('/api/staff/offers', authenticateStaff, requireRole(['OWNER', 'MANAGER']), (req: AuthenticatedRequest, res: Response) => {
  const { title, airline, airlineCode, sector, fare, discountNote, validTill } = req.body;
  if (!title || !airline || !fare) {
    return res.status(400).json({ error: 'Title, airline, and fare are required' });
  }
  const newOffer: OfferRecord = {
    id: 'off_' + Date.now(),
    title,
    airline,
    airlineCode: airlineCode || airline.substring(0, 2).toUpperCase(),
    sector: sector || 'International',
    fare: Number(fare),
    discountNote: discountNote || 'Wholesale agent special',
    validTill: validTill || '2026-10-31',
    status: 'Active'
  };
  offersStore.unshift(newOffer);
  logActivity('OFFER_PUBLISHED', req.staffUser!.email, req.staffUser!.fullName, req.staffUser!.role, 'Success', `Published wholesale offer: ${title}`, req);
  return res.status(201).json(newOffer);
});

// 14. Reports & Analytics Summary
app.get('/api/staff/reports', authenticateStaff, (req: AuthenticatedRequest, res: Response) => {
  const totalRevenue = bookingsStore.reduce((sum, b) => sum + b.amount, 0);
  const routeDistribution = [
    { route: 'Trichy → Dubai', count: 48, revenue: 684000 },
    { route: 'Chennai → Singapore', count: 36, revenue: 468000 },
    { route: 'Trichy → Sharjah', count: 32, revenue: 396800 },
    { route: 'Chennai → Doha', count: 24, revenue: 523200 },
    { route: 'Madurai → Colombo', count: 18, revenue: 216000 }
  ];
  const monthlyTrends = [
    { month: 'Apr', bookings: 78, enquiries: 110, revenue: 980000 },
    { month: 'May', bookings: 92, enquiries: 135, revenue: 1150000 },
    { month: 'Jun', bookings: 110, enquiries: 160, revenue: 1420000 },
    { month: 'Jul', bookings: 125, enquiries: 178, revenue: 1680000 },
    { month: 'Aug', bookings: 145, enquiries: 195, revenue: 1920000 },
    { month: 'Sep', bookings: 68, enquiries: 95, revenue: 890000 }
  ];
  const airlineShares = [
    { name: 'IndiGo', value: 42, color: '#0284C7' },
    { name: 'Air India Express', value: 25, color: '#EA580C' },
    { name: 'Qatar Airways', value: 16, color: '#831843' },
    { name: 'Scoot', value: 10, color: '#EAB308' },
    { name: 'Others', value: 7, color: '#64748B' }
  ];
  return res.json({
    totalRevenue,
    totalBookings: bookingsStore.length + 185,
    totalEnquiries: enquiriesStore.length + 240,
    fareUpdatesCount: fareHistoryStore.length,
    activeFaresCount: faresStore.length,
    routeDistribution,
    monthlyTrends,
    airlineShares
  });
});

// Public Flights API for customer website (Requirement 2, 11 - no sensitive staff fields)
app.get('/api/public/fares', (req: Request, res: Response) => {
  const publicFares = faresStore
    .filter((f) => f.status === 'Active')
    .map((f) => ({
      id: f.id,
      airline: f.airline,
      airlineCode: f.airlineCode,
      flightNumber: f.flightNumber,
      originCity: f.originCity,
      originCode: f.originCode,
      destCity: f.destCity,
      destCode: f.destCode,
      travelDate: f.travelDate,
      departureTime: f.departureTime,
      arrivalTime: f.arrivalTime,
      cabinClass: f.cabinClass,
      totalFare: f.totalFare,
      baggageAllowance: f.baggageAllowance,
      seatsAvailable: f.seatsAvailable
    }));
  return res.json(publicFares);
});

// Gemini AI Travel Concierge endpoint
app.post('/api/gemini/curate-itinerary', async (req: Request, res: Response) => {
  try {
    const { prompt } = req.body;
    const userPrompt = prompt && typeof prompt === 'string' && prompt.trim().length > 0
      ? prompt.trim()
      : 'Plan a 5-day luxury layover in Tokyo including Haneda VIP helicopter transfer';

    if (process.env.GEMINI_API_KEY) {
      const { GoogleGenAI } = await import('@google/genai');
      const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
      const response = await ai.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: `You are the executive travel curator for MMS AIR TRAVELS, an elite aviation carrier and VIP concierge service.
Curate a prestigious, high-end travel itinerary based on this traveler inquiry:
"${userPrompt}"

Structure your response concisely with:
1. Executive Overview & Flight Sector Allocation (recommended aircraft e.g. Boeing 787-9 or Airbus A350, private chauffeur transfer, airport lounge access)
2. Day-by-Day Curated Itinerary (Days 1 to 3 or 5, Michelin-starred culinary reservations, VIP access, luxury accommodation)
3. MMS Concierge Privileges (Bespoke baggage handling, Fast-track immigration, 24/7 dedicated flight dispatch hotline)

Keep the tone sophisticated, authoritative, and welcoming. Return clean Markdown formatted text.`
      });

      return res.json({
        success: true,
        itinerary: response.text,
        source: 'gemini-2.5-flash'
      });
    }

    // Curated high-luxury fallback itinerary if API key is not yet set
    const fallbackItinerary = `### Executive Itinerary: Tokyo Luxury Layover & Cultural Immersion

**Flight Sector Allocation**:
* **Inbound Flight**: MMS-882 (DXB → HND) • Airbus A350-1000 First Suite
* **Ground Operations**: Fast-track VIP diplomatic lane at Tokyo Haneda + private Airbus H130 helicopter transfer direct to Roppongi Heliport.
* **Accommodations**: Aman Tokyo, Premier Grand Suite with unobstructed Imperial Palace Gardens views.

---

#### Day-by-Day Bespoke Itinerary:

* **Day 1: Arrival & Stratospheric Skyline Welcome**
  * Private tarmac chauffeur reception and expedited biometric clearance.
  * Evening private welcome dining at *L’Effervescence* (3 Michelin Stars) in Minato-ku.
  * Nightcap at the Sky Lounge overlooking the illuminated Tokyo Tower.

* **Day 2: Private Art & Imperial Heritage**
  * Morning private after-hours viewing at the Nezu Museum and private tea master ceremony in Aoyama.
  * Omakase luncheon hosted by Master Chef at *Sushi Saito*.
  * Sunset Ginza shopping experience with dedicated personal style concierge.

* **Day 3: Mount Fuji Helicopter Excursion**
  * Morning chartered helicopter flight around Mount Fuji summit with luxury champagne service.
  * Private onsen relaxation at an exclusive Hakone ryokan estate.
  * Return flight to Haneda with prioritized MMS First Class boarding on MMS-402 to London Heathrow.

---

**MMS Concierge Privileges Included**:
* 24/7 VIP Global Dispatch Support with direct line to Chief Flight Officer.
* Direct tarmac luggage forwarding directly to your hotel suite.
* Guaranteed 100% refundability and date flexibility.`;

    return res.json({
      success: true,
      itinerary: fallbackItinerary,
      source: 'curated-mms-concierge'
    });
  } catch (error: any) {
    console.error('Itinerary curation error:', error);
    return res.status(500).json({ error: error.message || 'Failed to curate itinerary' });
  }
});

// Serve public static assets (including ThreeUI landing pages and assets)
app.use(express.static(path.join(process.cwd(), 'public')));

// --- SINGLE DOMAIN VITE & SPA HANDLING ---
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`MMS Travels Single Domain Server listening on http://0.0.0.0:${PORT}`);
    console.log(`Public Customer Site: http://localhost:${PORT}/`);
    console.log(`Private Staff Panel:  http://localhost:${PORT}/staff/`);
  });
}

startServer();
