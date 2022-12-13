﻿&НаСервере
Процедура ПриСозданииНаСервере(Отказ,СтандартнаяОбработка)
	
	//<Кошелев_16.06.2016; открытие этой формы из отчета>
	Доступно = ЗначениеЗаполнено(ЭтаФорма.Параметры.Сигнатура);
	Доступно = Доступно И ТипЗнч(ЭтаФорма.Параметры.Сигнатура) = Тип ("Строка");
	Если Доступно Тогда
		НЗ = РегистрыСведений.Звонки.СоздатьМенеджерЗаписи();
		НЗ.Сигнатура =ЭтаФорма.Параметры.Сигнатура;
		НЗ.Прочитать();
		Если НЗ.Выбран() Тогда
			ЗначениеВРеквизитФормы(НЗ, "Запись");
		Иначе
			Сообщить("ошибка");
			Отказ = Истина;
		КонецЕсли;
	КонецЕсли;
	//</Кошелев_16.06.2016>


// Сформируем заголовок и доступность формы
//-------------------------------------------------------------------------------------------------
	ЭтаФорма.Заголовок = ?(Запись.Принят,"Состоявшийся исходящий","Несостоявшийся исходящий") + " ";
	ЭтаФорма.Заголовок = ЭтаФорма.Заголовок + "от " + СокрЛП(Формат(Запись.Дата,"ДЛФ=DDT"));
	ЭтаФорма.Заголовок = ЭтаФорма.Заголовок + ", " + Конвертация.ДеньНеделиПрописью(Запись.Дата);
	ЭтаФорма.ТолькоПросмотр = Истина;

// Сведения об инициаторе звонка
//-------------------------------------------------------------------------------------------------
	Если (ЗначениеЗаполнено(Запись.Инициатор)) Тогда
		ВладСсылка = Телефония.ВладелецПолучить(Запись.Инициатор);
		ЭтаФорма.Источник = СокрЛП(Запись.Инициатор) + " (владелец не найден)";
		Элементы.Источник.Гиперссылка = Истина;

		Если (ЗначениеЗаполнено(ВладСсылка)) Тогда
			ЭтаФорма.Источник = СокрЛП(ВладСсылка.ТочкаРазмещения);
			ЭтаФорма.Источник = ЭтаФорма.Источник + " / " + СокрЛП(ВладСсылка.Наименование);
			ЭтаФорма.Источник = ЭтаФорма.Источник + " / " + СокрЛП(Запись.Инициатор);
		КонецЕсли;
	Иначе
		Элементы.Источник.ЦветТекста = Новый Цвет(255,0,0);
		ЭтаФорма.Источник = "Не определен";
	КонецЕсли;

// Сведения о внутреннем абоненте (приемнике) звонка
// Если реквизиты Инициатор и АбонентВнутренний совпадают, то элемент "Приемник" не показываем
//-------------------------------------------------------------------------------------------------
	Доступно = (ЗначениеЗаполнено(Запись.АбонентВнутренний));
	Доступно = Доступно И (Запись.Инициатор <> Запись.АбонентВнутренний);
	Элементы.Приемник.Видимость = Доступно;

	Если (Доступно = Истина) Тогда
		Если (ТипЗнч(Запись.АбонентВнутренний) = Тип("СправочникСсылка.ТелОчереди")) Тогда
			ЭтаФорма.Приемник = "Очередь " + СокрЛП(Запись.АбонентВнутренний) + " - ";
			ЭтаФорма.Приемник = ЭтаФорма.Приемник + СокрЛП(Запись.АбонентВнутренний.Назначение);
		Иначе
			ВладСсылка = Телефония.ВладелецПолучить(Запись.АбонентВнутренний);
			ЭтаФорма.Приемник = СокрЛП(Запись.АбонентВнутренний) + " (владелец не найден)";
			Элементы.Приемник.Гиперссылка = Истина;

			Если (ЗначениеЗаполнено(ВладСсылка)) Тогда
				ЭтаФорма.Приемник = СокрЛП(ВладСсылка.ТочкаРазмещения);
				ЭтаФорма.Приемник = ЭтаФорма.Приемник + " / " + СокрЛП(ВладСсылка.Наименование);
				ЭтаФорма.Приемник = ЭтаФорма.Приемник + " / " + СокрЛП(Запись.АбонентВнутренний);
			КонецЕсли;
		КонецЕсли;
	КонецЕсли;

// Сформируем видимость кнопок для прослушивания и сохранения звонка в файл
//-------------------------------------------------------------------------------------------------
	Элементы.ФайлЗаписиПрослушать.Видимость = Запись.Принят;
	Элементы.ФайлЗаписиСохранить.Видимость = Запись.Принят;

// Получим маршрут звонка
//-------------------------------------------------------------------------------------------------
	ТекстЗапроса = "
	|SELECT	Рег.Дата,Рег.КодСобытия,Рег.ИмяСобытия,Рег.Оператор,Прив.Владелец.ТочкаРазмещения AS ТочкаРазмещения,
	|		CASE WHEN (Рег.Оператор ССЫЛКА Справочник.ТелОчереди) THEN Рег.Оператор.Назначение ELSE Прив.Владелец.Наименование END AS Владелец,
	|		Рег.СвойстваСобытия AS СвойстваСобытия
	|FROM	РегистрСведений.ЗвонкиМаршруты Рег
	|LEFT	JOIN РегистрСведений.ОбъектыПривязка Прив ON (Прив.Объект = Рег.Оператор)
	|WHERE	(Рег.Сигнатура = &Сигнатура)
	|ORDER	BY Рег.НомерСобытия";

	Запрос = Новый Запрос;
	Запрос.Текст = ТекстЗапроса;
	Запрос.УстановитьПараметр("Сигнатура",ВРег(СокрЛП(Запись.Сигнатура)));
	Результат = Запрос.Выполнить().Выбрать();
	ЭтаФорма.Маршрут.Очистить();

	Пока (Результат.Следующий()) Цикл
		НовСтрока = ЭтаФорма.Маршрут.Добавить();
		НовСтрока.Дата 				= Результат.Дата;
		НовСтрока.Оператор			= СокрЛП(Результат.Оператор);
		НовСтрока.Владелец			= СокрЛП(Результат.Владелец);
		НовСтрока.КодСобытия		= Результат.КодСобытия;
		НовСтрока.Событие			= СокрЛП(Результат.ИмяСобытия);
		НовСтрока.ТочкаРазмещения 	= СокрЛП(Результат.ТочкаРазмещения);
		НовСтрока.СвойстваСобытия 	= СокрЛП(Результат.СвойстваСобытия);
	КонецЦикла;
КонецПроцедуры

//-------------------------------------------------------------------------------------------------

&НаКлиенте
Процедура ИсточникНажатие(Элемент,СтандартнаяОбработка)

// Получим ссылку на владельца внутреннего телефона
//-------------------------------------------------------------------------------------------------
	ВладСсылка = Телефония.ВладелецПолучить(Запись.Инициатор);
	ОткрываемоеЗначение = ?(ЗначениеЗаполнено(ВладСсылка),ВладСсылка,Запись.Инициатор);
	ОткрытьЗначение(ОткрываемоеЗначение);
	СтандартнаяОбработка = Ложь;
КонецПроцедуры

&НаКлиенте
Процедура ПриемникНажатие(Элемент,СтандартнаяОбработка)

// Получим ссылку на владельца внутреннего телефона
//-------------------------------------------------------------------------------------------------
	ВладСсылка = Телефония.ВладелецПолучить(Запись.АбонентВнутренний);
	ОткрываемоеЗначение = ?(ЗначениеЗаполнено(ВладСсылка),ВладСсылка,Запись.АбонентВнутренний);
	ОткрытьЗначение(ОткрываемоеЗначение);
	СтандартнаяОбработка = Ложь;
КонецПроцедуры
