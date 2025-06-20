import React, { useEffect, useState } from 'react';
import {
  checkin, checkout, getHistory,
  getLeaveHistory, submitLeaveRequest,
  getEmployeeSummary, getProfile,
  updateEmployeeProfile
} from '../services/api';
import { useNavigate } from 'react-router-dom';
import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import './EmployeeDashboard.css';
import { Pie } from 'react-chartjs-2';
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';
import { FaHome, FaUser, FaClock, FaRegCalendarAlt, FaCalendarAlt, FaHistory, FaSignOutAlt, FaTimes } from 'react-icons/fa';
import logo from '../assets/logooo.jpg';

ChartJS.register(ArcElement, Tooltip, Legend);

const bloodGroups = [
  "", "A+", "A-", "B+", "B-", "O+", "O-", "AB+", "AB-"
];

function to24HourFormat(hour, minute, ampm) {
  hour = parseInt(hour, 10);
  minute = minute.toString().padStart(2, "0");
  if (ampm === "PM" && hour !== 12) hour += 12;
  if (ampm === "AM" && hour === 12) hour = 0;
  return `${hour.toString().padStart(2, "0")}:${minute}`;
}
function to12HourFormat(time24) {
  if (!time24) return '';
  let [h, m] = time24.split(':');
  h = parseInt(h, 10);
  const ampm = h >= 12 ? 'PM' : 'AM';
  h = h % 12 || 12;
  return `${h}:${m} ${ampm}`;
}
function formatDateDMY(dateStr) {
  if (!dateStr) return "";
  const [y, m, d] = dateStr.split("-");
  return `${d}-${m}-${y}`;
}

const Sidebar = ({ activeTab, setActiveTab, handleLogout }) => (
  <aside className="sidebar">
    <div className="sidebar-logo">Employee</div>
    <ul>
      <li className={activeTab === 'dashboard' ? 'active' : ''} onClick={() => setActiveTab('dashboard')}><FaHome /> Dashboard</li>
      <li className={activeTab === 'profile' ? 'active' : ''} onClick={() => setActiveTab('profile')}><FaUser /> Profile</li>
      <li className={activeTab === 'attendance' ? 'active' : ''} onClick={() => setActiveTab('attendance')}><FaClock /> Attendance</li>
      <li className={activeTab === 'leave' ? 'active' : ''} onClick={() => setActiveTab('leave')}><FaRegCalendarAlt /> Leave Request</li>
      <li className={activeTab === 'holiday' ? 'active' : ''} onClick={() => setActiveTab('holiday')}><FaCalendarAlt /> Holiday Calendar</li>
      <li className={activeTab === 'history' ? 'active' : ''} onClick={() => setActiveTab('history')}><FaHistory /> Attendance History</li>
      <li onClick={handleLogout}><FaSignOutAlt /> Logout</li>
    </ul>
  </aside>
);

const TopNavbar = () => (
  <header className="dashboard-navbar">
    <div className="navbar-title">Employee Dashboard</div>
    <img src={logo} alt="Logo" className="navbar-logo-top-right" />
  </header>
);

const SummaryCards = ({ summary, leavesLeft, nextHoliday, employee }) => (
  <div className="summary-cards">
    <div className="card">
      <h4>Upcoming Holiday</h4>
      <p>
        <small>
          {nextHoliday ? `${nextHoliday.date} - ${nextHoliday.name}` : 'No upcoming holiday'}
        </small>
      </p>
    </div>
    <div className="card">
      <h4>Leaves Taken</h4>
      <p>{summary.leavesTaken}</p>
    </div>
    <div className="card">
      <h4>Leaves Left</h4>
      <p>{leavesLeft}</p>
    </div>
    <div className="card">
      <h4>Pending Requests</h4>
      <p>{summary.pendingRequests}</p>
    </div>
    <div className="card profile-summary-card">
      <div className="profile-avatar-small">👤</div>
      <div style={{ marginLeft: 8 }}>
        <div><strong>{employee.name}</strong></div>
        <div style={{ fontSize: 13 }}>{employee.email}</div>
        <div style={{ fontSize: 13 }}>{employee.department} | {employee.position}</div>
      </div>
    </div>
  </div>
);

const DashboardTab = ({ employee }) => {
  const data = {
    labels: ['Present', 'Absent'],
    datasets: [
      {
        label: 'Attendance',
        data: [85, 15],
        backgroundColor: ['#4caf50', '#f44336'],
        borderWidth: 0
      }
    ]
  };

  return (
    <div className="dashboard-profile-chart">
      <div className="card profile-summary">
        <div className="profile-avatar-large">👤</div>
        <h4>{employee.name}</h4>
        <p>{employee.email}</p>
        <div style={{ fontSize: 14, margin: "0.5rem 0" }}>{employee.department} | {employee.position}</div>
      </div>
      <div className="card small-chart">
        <h3>Attendance Overview</h3>
        <Pie data={data} />
      </div>
    </div>
  );
};

const AttendanceTab = ({ doj }) => {
  const [checkInHour, setCheckInHour] = useState("");
  const [checkInMinute, setCheckInMinute] = useState("");
  const [checkInAMPM, setCheckInAMPM] = useState("AM");
  const [checkOutHour, setCheckOutHour] = useState("");
  const [checkOutMinute, setCheckOutMinute] = useState("");
  const [checkOutAMPM, setCheckOutAMPM] = useState("AM");
  const [showCheckIn, setShowCheckIn] = useState(false);
  const [showCheckOut, setShowCheckOut] = useState(false);

  const [hasCheckedIn, setHasCheckedIn] = useState(false);
  const [hasCheckedOut, setHasCheckedOut] = useState(false);
  const [adminApproved, setAdminApproved] = useState(false);
  const [lastCheckIn, setLastCheckIn] = useState({ date: "", time: "", approved: false, status: "" });
  const [lastCheckOut, setLastCheckOut] = useState({ date: "", time: "" });
  const [pendingCheckoutMsg, setPendingCheckoutMsg] = useState("");
  const [approvalMsg, setApprovalMsg] = useState("");

  const today = new Date();
  const todayStr = today.toISOString().slice(0, 10);

  useEffect(() => {
    async function fetchLastAttendance() {
      try {
        const res = await getHistory();
        let checkedIn = false, checkedOut = false, adminOk = false, lastCI = {}, lastCO = {};
        let yesterdayPendingCheckout = false;
        let approval = false;
        let approvalText = "";
        let yesterdayDate = new Date(today);
        yesterdayDate.setDate(today.getDate() - 1);
        const yestStr = yesterdayDate.toISOString().slice(0, 10);

        if (Array.isArray(res.data)) {
          const sorted = res.data.slice().sort((a, b) => b.date.localeCompare(a.date));
          const todayRecord = sorted.find(r => r.date === todayStr);
          if (todayRecord && todayRecord.checkin) {
            checkedIn = true;
            adminOk = todayRecord.status === "Accepted" || todayRecord.approved === true;
            lastCI = {
              date: todayRecord.date,
              time: todayRecord.checkin,
              approved: adminOk,
              status: todayRecord.status
            };
            checkedOut = !!todayRecord.checkout;
            if (checkedOut) {
              lastCO = { date: todayRecord.date, time: todayRecord.checkout };
            }
          }
          const yestRecord = sorted.find(r => r.date === yestStr);
          if (yestRecord && yestRecord.checkin && !yestRecord.checkout) {
            yesterdayPendingCheckout = true;
          }
          if (adminOk && checkedIn && !checkedOut) {
            approval = true;
            approvalText = "✅ Your check-in has been approved.";
          }
        }
        setHasCheckedIn(checkedIn);
        setHasCheckedOut(checkedOut);
        setAdminApproved(adminOk);
        setLastCheckIn(lastCI);
        setLastCheckOut(lastCO);
        setApprovalMsg(approvalText);
        setPendingCheckoutMsg(
          yesterdayPendingCheckout
            ? "⛔ Yesterday's checkout is pending. Please check out for yesterday before you can check in today."
            : ""
        );
      } catch {
        toast.error("Failed to fetch attendance history");
      }
    }
    fetchLastAttendance();
  }, []);

  const checkInMinDate = doj || "";
  const checkInMaxDate = todayStr;
  const checkOutMinDate = doj || "";
  const checkOutMaxDate = todayStr;
  const isCheckInBlocked = !!pendingCheckoutMsg;
  const isCheckInDisabled = hasCheckedIn || isCheckInBlocked;
  const isCheckOutDisabled = !hasCheckedIn || hasCheckedOut || !adminApproved;

  const handleCheckIn = () => setShowCheckIn(true);

  const handleCheckInSubmit = async (e) => {
    e.preventDefault();
    if (!checkInHour || !checkInMinute || !checkInAMPM) {
      toast.error("Please select time for check-in.");
      return;
    }
    const dateToSend = todayStr;
    if (dateToSend < checkInMinDate) {
      toast.error("Cannot check in before your Date of Joining.");
      return;
    }
    if (dateToSend > checkInMaxDate) {
      toast.error("Cannot check in for future dates.");
      return;
    }
    setShowCheckIn(false);
    try {
      const time24 = to24HourFormat(checkInHour, checkInMinute, checkInAMPM);
      const dateTime = `${dateToSend}T${time24}`;
      await checkin({ datetime: dateTime });
      setLastCheckIn({ date: dateToSend, time: `${checkInHour.padStart(2, "0")}:${checkInMinute.padStart(2, "0")} ${checkInAMPM}`, approved: false });
      setHasCheckedIn(true);
      setAdminApproved(false);
      setApprovalMsg("");
      toast.success("Check-in submitted for approval!");
    } catch (err) {
      toast.error(err?.response?.data?.msg || "Check-in failed");
      setHasCheckedIn(false);
      setAdminApproved(false);
      setApprovalMsg("");
    }
  };

  const handleCheckOut = () => setShowCheckOut(true);

  const handleCheckOutSubmit = async (e) => {
    e.preventDefault();
    if (!checkOutHour || !checkOutMinute || !checkOutAMPM) {
      toast.error("Please select time for check-out.");
      return;
    }
    const dateToSend = todayStr;
    if (dateToSend < checkOutMinDate) {
      toast.error("Cannot check out before your Date of Joining.");
      return;
    }
    if (dateToSend > checkOutMaxDate) {
      toast.error("Cannot check out for future dates.");
      return;
    }
    setShowCheckOut(false);
    try {
      const time24 = to24HourFormat(checkOutHour, checkOutMinute, checkOutAMPM);
      const dateTime = `${dateToSend}T${time24}`;
      await checkout({ datetime: dateTime });
      setLastCheckOut({ date: dateToSend, time: `${checkOutHour.padStart(2, "0")}:${checkOutMinute.padStart(2, "0")} ${checkOutAMPM}` });
      setHasCheckedOut(true);
      toast.success("Checked out successfully!");
    } catch (err) {
      toast.error(err?.response?.data?.msg || "Check-out failed");
      setHasCheckedOut(false);
    }
  };

  const renderTimeSelector = (hour, setHour, minute, setMinute, ampm, setAMPM) => (
    <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
      <input
        type="number"
        min="1"
        max="12"
        value={hour}
        onChange={e => {
          let val = e.target.value;
          if (val === "" || (parseInt(val, 10) >= 1 && parseInt(val, 10) <= 12)) setHour(val.replace(/^0+/, "") || "");
        }}
        required
        style={{ width: 48 }}
        placeholder="HH"
      />
      <span>:</span>
      <input
        type="number"
        min="0"
        max="59"
        value={minute}
        onChange={e => {
          let val = e.target.value;
          if (val === "" || (parseInt(val, 10) >= 0 && parseInt(val, 10) <= 59)) setMinute(val.replace(/^0+/, "") || "");
        }}
        required
        style={{ width: 48 }}
        placeholder="MM"
      />
      <select
        value={ampm}
        onChange={e => setAMPM(e.target.value)}
        style={{ width: 60 }}
      >
        <option value="AM">AM</option>
        <option value="PM">PM</option>
      </select>
    </div>
  );

  return (
    <div className="card" style={{ position: "relative" }}>
      {isCheckInBlocked && (
        <div style={{ color: "#c0392b", marginBottom: "1rem", fontWeight: 500, textAlign: "center" }}>
          {pendingCheckoutMsg}
        </div>
      )}
      {approvalMsg && (
        <div style={{ color: "#27ae60", marginBottom: "1rem", fontWeight: 500, textAlign: "center" }}>
          {approvalMsg}
        </div>
      )}
      <div className="btn-group">
        <button
          onClick={handleCheckIn}
          disabled={isCheckInDisabled}
          style={isCheckInDisabled ? { opacity: 0.5, cursor: 'not-allowed' } : {}}
        >
          Check In
        </button>
        <button
          onClick={handleCheckOut}
          disabled={isCheckOutDisabled}
          style={isCheckOutDisabled ? { opacity: 0.5, cursor: 'not-allowed' } : {}}
        >
          Check Out
        </button>
      </div>
      {showCheckIn && (
        <form className="attendance-form-modal" onSubmit={handleCheckInSubmit} style={{ position: "relative" }}>
          <button
            type="button"
            className="close-btn"
            title="Cancel"
            style={{
              background: "none",
              border: "none",
              fontSize: 18,
              color: "#888",
              cursor: "pointer",
              position: "absolute",
              right: 12,
              top: 8,
              zIndex: 2
            }}
            onClick={() => setShowCheckIn(false)}
          >
            <FaTimes />
          </button>
          <label>
            Date
            <input
              type="date"
              value={todayStr}
              readOnly
              className="calendar-input"
            />
          </label>
          <label>
            Time
            {renderTimeSelector(checkInHour, setCheckInHour, checkInMinute, setCheckInMinute, checkInAMPM, setCheckInAMPM)}
          </label>
          <div>
            <button type="submit">Submit</button>
          </div>
        </form>
      )}
      {showCheckOut && (
        <form className="attendance-form-modal" onSubmit={handleCheckOutSubmit} style={{ position: "relative" }}>
          <button
            type="button"
            className="close-btn"
            title="Cancel"
            style={{
              background: "none",
              border: "none",
              fontSize: 18,
              color: "#888",
              cursor: "pointer",
              position: "absolute",
              right: 12,
              top: 8,
              zIndex: 2
            }}
            onClick={() => setShowCheckOut(false)}
          >
            <FaTimes />
          </button>
          <label>
            Date
            <input
              type="date"
              value={todayStr}
              readOnly
              className="calendar-input"
            />
          </label>
          <label>
            Time
            {renderTimeSelector(checkOutHour, setCheckOutHour, checkOutMinute, setCheckOutMinute, checkOutAMPM, setCheckOutAMPM)}
          </label>
          <div>
            <button type="submit">Submit</button>
          </div>
        </form>
      )}
      {lastCheckIn.date && lastCheckIn.time && (
        <p style={{ marginTop: '1rem', fontSize: '14px' }}>
          ✅ Checked in at: <strong>{formatDateDMY(lastCheckIn.date)} {lastCheckIn.time}</strong>
          {lastCheckIn.approved === false ? <span style={{ color: "#f39c12" }}> (Pending admin approval)</span>
            : lastCheckIn.status === "Accepted" ? <span style={{ color: "#27ae60" }}> (Approved)</span>
              : ""}
        </p>
      )}
      {lastCheckOut.date && lastCheckOut.time && (
        <p style={{ marginTop: '0.7rem', fontSize: '14px' }}>
          ✅ Checked out at: <strong>{formatDateDMY(lastCheckOut.date)} {lastCheckOut.time}</strong>
        </p>
      )}
    </div>
  );
};

const LeaveTab = () => {
  const [leaveDate, setLeaveDate] = useState('');
  const [reason, setReason] = useState('');
  const [leaveHistory, setLeaveHistory] = useState([]);
  const [page, setPage] = useState(1);
  const perPage = 5;

  useEffect(() => {
    getLeaveHistory()
      .then(res => setLeaveHistory(res.data || []))
      .catch(() => setLeaveHistory([]));
  }, []);

  const handleLeaveSubmit = async (e) => {
    e.preventDefault();
    try {
      await submitLeaveRequest({ date: leaveDate, reason });
      toast.success('Leave request submitted');
      setLeaveDate('');
      setReason('');
      getLeaveHistory().then(res => setLeaveHistory(res.data || []));
    } catch {
      toast.error('Failed to submit leave request');
    }
  };

  const startIdx = (page - 1) * perPage;
  const pageData = leaveHistory.slice(startIdx, startIdx + perPage);
  const totalPages = Math.ceil(leaveHistory.length / perPage);

  return (
    <div className="leave-tab-grid">
      <div className="leave-form-card">
        <h3>Leave Request Form</h3>
        <form className="leave-form" onSubmit={handleLeaveSubmit}>
          <label>
            Leave Date
            <input
              type="date"
              value={leaveDate}
              onChange={e => setLeaveDate(e.target.value)}
              placeholder="dd / mm / yyyy"
              required
              className="calendar-input"
            />
          </label>
          <label>
            Reason
            <textarea
              value={reason}
              onChange={e => setReason(e.target.value)}
              placeholder="Enter the reason for leave"
              required
            />
          </label>
          <button type="submit" className="apply-btn">Apply Leave</button>
        </form>
      </div>
      <div className="leave-history-card">
        <h4>Leave History</h4>
        <table>
          <thead>
            <tr>
              <th>Date</th>
              <th>Reason</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {pageData.length === 0 ? (
              <tr>
                <td colSpan={3} style={{ textAlign: 'center' }}>No leave history</td>
              </tr>
            ) : (
              pageData.map((leave, idx) => (
                <tr key={idx}>
                  <td>{leave.date}</td>
                  <td>{leave.reason}</td>
                  <td>{leave.status}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
        {totalPages > 1 && (
          <div className="pagination capsule">
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page === 1}
              className="capsule-btn"
            >
              Previous
            </button>
            <span className="capsule-page">{page} / {totalPages}</span>
            <button
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
              className="capsule-btn"
            >
              Next
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

const holidays = [
  { date: '2025-01-26', name: 'Republic Day' },
  { date: '2025-03-08', name: 'Maha Shivratri' },
  { date: '2025-04-14', name: 'Ambedkar Jayanti' },
  { date: '2025-05-01', name: 'May Day' },
  { date: '2025-06-06', name: 'Eid al-Fitr' },
  { date: '2025-08-15', name: 'Independence Day' },
  { date: '2025-08-27', name: 'Ganesh Chaturthi' },
  { date: '2025-10-02', name: 'Gandhi Jayanti' },
  { date: '2025-10-20', name: 'Diwali' },
  { date: '2025-11-01', name: 'Kannada Rajyotsava' },
  { date: '2025-11-14', name: "Children's Day" },
  { date: '2025-12-25', name: 'Christmas' }
];

const getNextHoliday = () => {
  const today = new Date();
  return holidays.find(h => new Date(h.date) >= today) || null;
};

const HolidayTab = () => {
  const [page, setPage] = useState(1);
  const perPage = 5;
  const totalPages = Math.ceil(holidays.length / perPage);
  const pageData = holidays.slice((page - 1) * perPage, page * perPage);

  return (
    <div className="card holiday-card">
      <h3>Holiday Calendar</h3>
      <table className="holiday-table">
        <thead>
          <tr><th>Date</th><th>Holiday</th></tr>
        </thead>
        <tbody>
          {pageData.map((h, idx) => (
            <tr key={idx}>
              <td>{h.date}</td>
              <td>{h.name}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {totalPages > 1 && (
        <div className="pagination capsule">
          <button
            onClick={() => setPage(p => Math.max(1, p - 1))}
            disabled={page === 1}
            className="capsule-btn"
          >
            Previous
          </button>
          <span className="capsule-page">{page} / {totalPages}</span>
          <button
            onClick={() => setPage(p => Math.min(totalPages, p + 1))}
            disabled={page === totalPages}
            className="capsule-btn"
          >
            Next
          </button>
        </div>
      )}
    </div>
  );
};

const HistoryTab = () => {
  const [history, setHistory] = useState([]);

  useEffect(() => {
    const fetchHistory = async () => {
      try {
        const res = await getHistory();
        setHistory(res.data);
      } catch (err) {
        console.error(err);
        toast.error('Failed to load attendance history');
      }
    };
    fetchHistory();
  }, []);

  return (
    <div className="card">
      <h3>Attendance History</h3>
      <table>
        <thead>
          <tr><th>Date</th><th>Check-in</th><th>Check-out</th></tr>
        </thead>
        <tbody>
          {history.length === 0 ? (
            <tr><td colSpan="3">No records found</td></tr>
          ) : (
            history.map((record, i) => (
              <tr key={i}>
                <td>{formatDateDMY(record.date)}</td>
                <td>{record.checkin ? to12HourFormat(record.checkin) : '—'}</td>
                <td>{record.checkout ? to12HourFormat(record.checkout) : '—'}</td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
};

const ProfileTab = ({ employee, setEditMode, editMode, onSave }) => (
  <div className="card profile-view">
    <div className="profile-avatar-large">👤</div>
    {!editMode ? (
      <>
        <p><strong>Name:</strong> {employee.name}</p>
        <p><strong>Email:</strong> {employee.email}</p>
        <p><strong>Position:</strong> {employee.position}</p>
        <p><strong>Department:</strong> {employee.department}</p>
        <p><strong>Blood Group:</strong> {employee.bloodGroup || "-"}</p>
        <p><strong>Date of Joining:</strong> {formatDateDMY(employee.doj)}</p>
        <div className="edit-button-container">
          <button className="edit-btn" onClick={() => setEditMode(true)}>Edit Profile</button>
        </div>
      </>
    ) : (
      <form onSubmit={onSave} className="profile-form">
        <div style={{ display: "flex", justifyContent: "flex-end" }}>
          <button
            type="button"
            className="close-btn"
            onClick={() => setEditMode(false)}
            title="Cancel"
            style={{
              background: "none",
              border: "none",
              fontSize: 18,
              color: "#888",
              cursor: "pointer",
              position: "absolute",
              right: 16,
              top: 12,
            }}
          >
            <FaTimes />
          </button>
        </div>
        <label>Name
          <input type="text" name="name" defaultValue={employee.name} placeholder="Enter your full name" required />
        </label>
        <label>Email
          <input type="email" name="email" defaultValue={employee.email} placeholder="Enter your email address" required />
        </label>
        <label>Blood Group
          <select
            name="bloodGroup"
            defaultValue={employee.bloodGroup}
            required
            style={{
              width: "95%",
              minWidth: 0,
              fontSize: "1.08rem",
              padding: "9px 12px",
              border: "1px solid #ccc",
              borderRadius: "7px",
              background: "#fcfcfc",
              boxSizing: "border-box",
              marginBottom: "0.3rem",
              outline: "none",
              transition: "border-color 0.2s",
              height: "38px",
              alignItems: "center",
            }}
          >
            <option value="">Select Blood Group</option>
            {bloodGroups.filter(bg => bg !== "").map(bg => (
              <option key={bg} value={bg}>{bg}</option>
            ))}
          </select>
        </label>
        <div className="modal-buttons">
          <button type="submit">Update</button>
        </div>
      </form>
    )}
  </div>
);

const EmployeeDashboard = () => {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [summary, setSummary] = useState({ leavesTaken: 0, pendingRequests: 0 });
  const [employee, setEmployee] = useState({ name: '', email: '', position: '', department: '', doj: '', bloodGroup: '' });
  const [editMode, setEditMode] = useState(false);

  const navigate = useNavigate();
  const leavesLeft = 20 - summary.leavesTaken;

  const nextHoliday = getNextHoliday();

  useEffect(() => {
    getProfile().then(res => setEmployee(res.data)).catch(() => toast.error('Failed to load profile'));
    getEmployeeSummary().then(res => setSummary(res.data)).catch(() => toast.error('Failed to load dashboard data'));
  }, []);

  const handleLogout = () => {
    localStorage.clear();
    navigate('/');
  };

  const handleProfileSave = async (e) => {
    e.preventDefault();
    const form = e.target;
    const updated = {
      name: form.name.value,
      email: form.email.value,
      bloodGroup: form.bloodGroup.value,
    };
    try {
      await updateEmployeeProfile(updated);
      setEmployee({
        ...employee,
        ...updated,
      });
      setEditMode(false);
      toast.success('Profile updated successfully');
    } catch (err) {
      toast.error('Update failed');
    }
  };

  return (
    <div className="dashboard-container">
      <Sidebar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        handleLogout={handleLogout}
      />
      <div className="main-area">
        <TopNavbar />
        <main className="main-content">
          <SummaryCards summary={summary} leavesLeft={leavesLeft} nextHoliday={nextHoliday} employee={employee} />
          {activeTab === 'dashboard' && <DashboardTab employee={employee} />}
          {activeTab === 'profile' && <ProfileTab employee={employee} setEditMode={setEditMode} editMode={editMode} onSave={handleProfileSave} />}
          {activeTab === 'attendance' && <AttendanceTab doj={employee.doj} />}
          {activeTab === 'history' && <HistoryTab />}
          {activeTab === 'leave' && <LeaveTab />}
          {activeTab === 'holiday' && <HolidayTab />}
          <ToastContainer />
        </main>
      </div>
    </div>
  );
};

export default EmployeeDashboard;